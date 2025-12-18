"""
ISO 27001:2022 Framework Implementation for Attestful.

Provides ISO 27001:2022 Annex A control definitions and AWS compliance checks
mapped to ISO controls. Supports Statement of Applicability (SoA) generation.

ISO 27001:2022 Annex A Control Domains:
- A.5: Organizational controls (37 controls)
- A.6: People controls (8 controls)
- A.7: Physical controls (14 controls)
- A.8: Technological controls (34 controls)

Total: 93 controls (reduced from 114 in ISO 27001:2013)
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

ISO_27001_FRAMEWORK_ID = "iso-27001"
ISO_27001_VERSION = "2022"

# Control domains
DOMAIN_ORGANIZATIONAL = "A.5"
DOMAIN_PEOPLE = "A.6"
DOMAIN_PHYSICAL = "A.7"
DOMAIN_TECHNOLOGICAL = "A.8"


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class ISO27001Control:
    """
    Represents an ISO 27001:2022 Annex A control.

    Attributes:
        id: Control identifier (e.g., "A.5.1").
        title: Control title.
        description: Control description/guidance.
        domain: Control domain (A.5, A.6, A.7, A.8).
        objective: Control objective.
        attributes: Control attributes (preventive, detective, corrective).
        nist_mappings: Mapped NIST 800-53 control IDs.
        soc2_mappings: Mapped SOC 2 Trust Services Criteria.
    """

    id: str
    title: str
    description: str
    domain: str
    objective: str = ""
    attributes: list[str] = field(default_factory=lambda: ["preventive"])
    nist_mappings: list[str] = field(default_factory=list)
    soc2_mappings: list[str] = field(default_factory=list)


@dataclass
class ISO27001Framework:
    """
    ISO 27001:2022 framework implementation.

    Attributes:
        version: Framework version (2022).
        controls: Dictionary of controls by ID.
        check_mappings: Mapping of control IDs to check IDs.
    """

    version: str = ISO_27001_VERSION
    controls: dict[str, ISO27001Control] = field(default_factory=dict)
    check_mappings: dict[str, list[str]] = field(default_factory=dict)

    def get_control(self, control_id: str) -> ISO27001Control | None:
        """Get a control by ID."""
        return self.controls.get(control_id)

    def get_checks_for_control(self, control_id: str) -> list[str]:
        """Get check IDs mapped to a control."""
        return self.check_mappings.get(control_id, [])

    def get_controls_by_domain(self, domain: str) -> list[ISO27001Control]:
        """Get all controls in a domain."""
        return [c for c in self.controls.values() if c.domain == domain]

    def get_statement_of_applicability(self) -> dict[str, dict[str, Any]]:
        """
        Generate a Statement of Applicability (SoA) template.

        Returns:
            Dictionary with control ID as key and SoA details as value.
        """
        soa = {}
        for control_id, control in self.controls.items():
            soa[control_id] = {
                "title": control.title,
                "domain": control.domain,
                "applicable": True,
                "justification": "",
                "implementation_status": "not_implemented",
                "evidence": [],
            }
        return soa


# =============================================================================
# ISO 27001:2022 Annex A Control Definitions
# =============================================================================

ISO_27001_CONTROLS: dict[str, ISO27001Control] = {
    # =========================================================================
    # A.5 Organizational Controls
    # =========================================================================
    "A.5.1": ISO27001Control(
        id="A.5.1",
        title="Policies for information security",
        description="Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals and if significant changes occur.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To provide management direction and support for information security in accordance with business requirements and relevant laws and regulations.",
        attributes=["preventive"],
        nist_mappings=["PL-1", "PM-1"],
        soc2_mappings=["CC1.1", "CC1.2"],
    ),
    "A.5.2": ISO27001Control(
        id="A.5.2",
        title="Information security roles and responsibilities",
        description="Information security roles and responsibilities shall be defined and allocated according to the organization needs.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To establish a defined and supported management structure to initiate and control the implementation and operation of information security within the organization.",
        attributes=["preventive"],
        nist_mappings=["PM-2", "PS-2"],
        soc2_mappings=["CC1.3"],
    ),
    "A.5.3": ISO27001Control(
        id="A.5.3",
        title="Segregation of duties",
        description="Conflicting duties and conflicting areas of responsibility shall be segregated.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To reduce opportunities for unauthorized or unintentional modification or misuse of the organization's assets.",
        attributes=["preventive"],
        nist_mappings=["AC-5"],
        soc2_mappings=["CC5.1"],
    ),
    "A.5.4": ISO27001Control(
        id="A.5.4",
        title="Management responsibilities",
        description="Management shall require all personnel to apply information security in accordance with the established information security policy, topic-specific policies and procedures of the organization.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure management support for information security implementation.",
        attributes=["preventive"],
        nist_mappings=["PM-1", "PM-13"],
        soc2_mappings=["CC1.4"],
    ),
    "A.5.5": ISO27001Control(
        id="A.5.5",
        title="Contact with authorities",
        description="The organization shall establish and maintain contact with relevant authorities.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure appropriate contact with relevant authorities.",
        attributes=["preventive", "corrective"],
        nist_mappings=["IR-6", "PM-15"],
        soc2_mappings=["CC2.1"],
    ),
    "A.5.6": ISO27001Control(
        id="A.5.6",
        title="Contact with special interest groups",
        description="The organization shall establish and maintain contact with special interest groups or other specialist security forums and professional associations.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure appropriate contact with special interest groups.",
        attributes=["preventive"],
        nist_mappings=["PM-15", "PM-16"],
        soc2_mappings=["CC2.2"],
    ),
    "A.5.7": ISO27001Control(
        id="A.5.7",
        title="Threat intelligence",
        description="Information relating to information security threats shall be collected and analysed to produce threat intelligence.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To provide awareness of the organization's threat environment.",
        attributes=["preventive", "detective"],
        nist_mappings=["PM-16", "RA-3", "SI-5"],
        soc2_mappings=["CC3.2"],
    ),
    "A.5.8": ISO27001Control(
        id="A.5.8",
        title="Information security in project management",
        description="Information security shall be integrated into project management.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure information security is addressed in project management.",
        attributes=["preventive"],
        nist_mappings=["SA-3", "SA-15"],
        soc2_mappings=["CC3.1"],
    ),
    "A.5.9": ISO27001Control(
        id="A.5.9",
        title="Inventory of information and other associated assets",
        description="An inventory of information and other associated assets, including owners, shall be developed and maintained.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To identify the organization's information and other associated assets.",
        attributes=["preventive"],
        nist_mappings=["CM-8", "PM-5"],
        soc2_mappings=["CC6.1"],
    ),
    "A.5.10": ISO27001Control(
        id="A.5.10",
        title="Acceptable use of information and other associated assets",
        description="Rules for the acceptable use and procedures for handling information and other associated assets shall be identified, documented and implemented.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure information and other associated assets are appropriately protected, used and handled.",
        attributes=["preventive"],
        nist_mappings=["PL-4", "AC-20"],
        soc2_mappings=["CC6.2"],
    ),
    "A.5.11": ISO27001Control(
        id="A.5.11",
        title="Return of assets",
        description="Personnel and other interested parties as appropriate shall return all the organization's assets in their possession upon change or termination of their employment, contract or agreement.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To protect the organization's assets as part of the process of changing or terminating employment, contract or agreement.",
        attributes=["preventive"],
        nist_mappings=["PS-4"],
        soc2_mappings=["CC6.3"],
    ),
    "A.5.12": ISO27001Control(
        id="A.5.12",
        title="Classification of information",
        description="Information shall be classified according to the information security needs of the organization based on confidentiality, integrity, availability and relevant interested party requirements.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure that information receives an appropriate level of protection.",
        attributes=["preventive"],
        nist_mappings=["RA-2", "SC-16"],
        soc2_mappings=["CC6.1"],
    ),
    "A.5.13": ISO27001Control(
        id="A.5.13",
        title="Labelling of information",
        description="An appropriate set of procedures for information labelling shall be developed and implemented in accordance with the information classification scheme adopted by the organization.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure that information labelling supports the classification scheme.",
        attributes=["preventive"],
        nist_mappings=["MP-3", "SC-16"],
        soc2_mappings=["CC6.1"],
    ),
    "A.5.14": ISO27001Control(
        id="A.5.14",
        title="Information transfer",
        description="Information transfer rules, procedures, or agreements shall be in place for all types of transfer facilities within the organization and between the organization and other parties.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To maintain the security of information transferred within an organization and with any external entity.",
        attributes=["preventive"],
        nist_mappings=["SC-8", "SC-13"],
        soc2_mappings=["CC6.6", "CC6.7"],
    ),
    "A.5.15": ISO27001Control(
        id="A.5.15",
        title="Access control",
        description="Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure authorized access and to prevent unauthorized access to information and other associated assets.",
        attributes=["preventive"],
        nist_mappings=["AC-1", "AC-2", "AC-3"],
        soc2_mappings=["CC6.1", "CC6.2", "CC6.3"],
    ),
    "A.5.16": ISO27001Control(
        id="A.5.16",
        title="Identity management",
        description="The full lifecycle of identities shall be managed.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To allow for unique identification of individuals and systems accessing the organization's information and other associated assets.",
        attributes=["preventive"],
        nist_mappings=["IA-1", "IA-4", "IA-5"],
        soc2_mappings=["CC6.1"],
    ),
    "A.5.17": ISO27001Control(
        id="A.5.17",
        title="Authentication information",
        description="Allocation and management of authentication information shall be controlled by a management process, including advising personnel on appropriate handling of authentication information.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure proper handling of authentication information.",
        attributes=["preventive"],
        nist_mappings=["IA-5", "IA-6"],
        soc2_mappings=["CC6.1"],
    ),
    "A.5.18": ISO27001Control(
        id="A.5.18",
        title="Access rights",
        description="Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed in accordance with the organization's topic-specific policy on and rules for access control.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure that access to information and other associated assets is authorized and appropriate.",
        attributes=["preventive"],
        nist_mappings=["AC-2", "AC-6"],
        soc2_mappings=["CC6.2", "CC6.3"],
    ),
    "A.5.19": ISO27001Control(
        id="A.5.19",
        title="Information security in supplier relationships",
        description="Processes and procedures shall be defined and implemented to manage the information security risks associated with the use of supplier's products or services.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To maintain an agreed level of information security in supplier relationships.",
        attributes=["preventive"],
        nist_mappings=["SA-9", "SR-1"],
        soc2_mappings=["CC9.2"],
    ),
    "A.5.20": ISO27001Control(
        id="A.5.20",
        title="Addressing information security within supplier agreements",
        description="Relevant information security requirements shall be established and agreed with each supplier based on the type of supplier relationship.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure information security is addressed in supplier agreements.",
        attributes=["preventive"],
        nist_mappings=["SA-4", "SA-9"],
        soc2_mappings=["CC9.2"],
    ),
    "A.5.21": ISO27001Control(
        id="A.5.21",
        title="Managing information security in the ICT supply chain",
        description="Processes and procedures shall be defined and implemented to manage the information security risks associated with the ICT products and services supply chain.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To maintain an agreed level of information security in supplier relationships.",
        attributes=["preventive"],
        nist_mappings=["SR-3", "SR-5", "SR-6"],
        soc2_mappings=["CC9.2"],
    ),
    "A.5.22": ISO27001Control(
        id="A.5.22",
        title="Monitoring, review and change management of supplier services",
        description="The organization shall regularly monitor, review, evaluate and manage change in supplier information security practices and service delivery.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To maintain an agreed level of information security and service delivery.",
        attributes=["detective"],
        nist_mappings=["SA-9", "CA-7"],
        soc2_mappings=["CC9.2"],
    ),
    "A.5.23": ISO27001Control(
        id="A.5.23",
        title="Information security for use of cloud services",
        description="Processes for acquisition, use, management and exit from cloud services shall be established in accordance with the organization's information security requirements.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To specify and manage information security for the use of cloud services.",
        attributes=["preventive"],
        nist_mappings=["SA-9", "AC-20"],
        soc2_mappings=["CC9.2"],
    ),
    "A.5.24": ISO27001Control(
        id="A.5.24",
        title="Information security incident management planning and preparation",
        description="The organization shall plan and prepare for managing information security incidents by defining, establishing and communicating information security incident management processes, roles and responsibilities.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure a quick, effective and orderly response to information security incidents.",
        attributes=["preventive", "corrective"],
        nist_mappings=["IR-1", "IR-8"],
        soc2_mappings=["CC7.3", "CC7.4"],
    ),
    "A.5.25": ISO27001Control(
        id="A.5.25",
        title="Assessment and decision on information security events",
        description="The organization shall assess information security events and decide if they are to be categorized as information security incidents.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure effective categorization and prioritization of information security events.",
        attributes=["detective"],
        nist_mappings=["IR-4", "IR-5"],
        soc2_mappings=["CC7.3"],
    ),
    "A.5.26": ISO27001Control(
        id="A.5.26",
        title="Response to information security incidents",
        description="Information security incidents shall be responded to in accordance with the documented procedures.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure a quick, effective and orderly response to information security incidents.",
        attributes=["corrective"],
        nist_mappings=["IR-4", "IR-6"],
        soc2_mappings=["CC7.4", "CC7.5"],
    ),
    "A.5.27": ISO27001Control(
        id="A.5.27",
        title="Learning from information security incidents",
        description="Knowledge gained from information security incidents shall be used to strengthen and improve the information security controls.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To reduce the likelihood or impact of future incidents.",
        attributes=["corrective"],
        nist_mappings=["IR-4", "IR-6"],
        soc2_mappings=["CC7.5"],
    ),
    "A.5.28": ISO27001Control(
        id="A.5.28",
        title="Collection of evidence",
        description="The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence related to information security events.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure that evidence is properly collected for follow-up.",
        attributes=["detective"],
        nist_mappings=["AU-9", "IR-4"],
        soc2_mappings=["CC7.4"],
    ),
    "A.5.29": ISO27001Control(
        id="A.5.29",
        title="Information security during disruption",
        description="The organization shall plan how to maintain information security at an appropriate level during disruption.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure information security continuity.",
        attributes=["preventive", "corrective"],
        nist_mappings=["CP-2", "CP-7"],
        soc2_mappings=["A1.2"],
    ),
    "A.5.30": ISO27001Control(
        id="A.5.30",
        title="ICT readiness for business continuity",
        description="ICT readiness shall be planned, implemented, maintained and tested based on business continuity objectives and ICT continuity requirements.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure the availability of the organization's information and other associated assets during disruption.",
        attributes=["preventive"],
        nist_mappings=["CP-2", "CP-10"],
        soc2_mappings=["A1.2", "A1.3"],
    ),
    "A.5.31": ISO27001Control(
        id="A.5.31",
        title="Legal, statutory, regulatory and contractual requirements",
        description="Legal, statutory, regulatory and contractual requirements relevant to information security and the organization's approach to meet these requirements shall be identified, documented and kept up to date.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure compliance with legal, statutory, regulatory and contractual requirements.",
        attributes=["preventive"],
        nist_mappings=["PL-4", "SA-9"],
        soc2_mappings=["CC2.2", "CC2.3"],
    ),
    "A.5.32": ISO27001Control(
        id="A.5.32",
        title="Intellectual property rights",
        description="The organization shall implement appropriate procedures to protect intellectual property rights.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure compliance with intellectual property rights.",
        attributes=["preventive"],
        nist_mappings=["PM-11"],
        soc2_mappings=["CC2.3"],
    ),
    "A.5.33": ISO27001Control(
        id="A.5.33",
        title="Protection of records",
        description="Records shall be protected from loss, destruction, falsification, unauthorized access and unauthorized release.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure the protection of records.",
        attributes=["preventive"],
        nist_mappings=["AU-9", "AU-11"],
        soc2_mappings=["CC6.1"],
    ),
    "A.5.34": ISO27001Control(
        id="A.5.34",
        title="Privacy and protection of PII",
        description="The organization shall identify and meet the requirements regarding the preservation of privacy and protection of PII according to applicable laws and regulations and contractual requirements.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure privacy and protection of PII.",
        attributes=["preventive"],
        nist_mappings=["PT-1", "PT-2"],
        soc2_mappings=["P1.1", "P2.1"],
    ),
    "A.5.35": ISO27001Control(
        id="A.5.35",
        title="Independent review of information security",
        description="The organization's approach to managing information security and its implementation including people, processes and technologies shall be reviewed independently at planned intervals, or when significant changes occur.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure the suitability, adequacy and effectiveness of information security.",
        attributes=["detective"],
        nist_mappings=["CA-2", "CA-7"],
        soc2_mappings=["CC4.1", "CC4.2"],
    ),
    "A.5.36": ISO27001Control(
        id="A.5.36",
        title="Compliance with policies, rules and standards for information security",
        description="Compliance with the organization's information security policy, topic-specific policies, rules and standards shall be regularly reviewed.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure that information security is implemented and operated in accordance with the organizational policies and procedures.",
        attributes=["detective"],
        nist_mappings=["CA-2", "CA-7", "PM-6"],
        soc2_mappings=["CC4.1"],
    ),
    "A.5.37": ISO27001Control(
        id="A.5.37",
        title="Documented operating procedures",
        description="Operating procedures for information processing facilities shall be documented and made available to personnel who need them.",
        domain=DOMAIN_ORGANIZATIONAL,
        objective="To ensure correct and secure operations of information processing facilities.",
        attributes=["preventive"],
        nist_mappings=["SA-5", "CM-3"],
        soc2_mappings=["CC5.2"],
    ),
    # =========================================================================
    # A.6 People Controls
    # =========================================================================
    "A.6.1": ISO27001Control(
        id="A.6.1",
        title="Screening",
        description="Background verification checks on all candidates to become personnel shall be carried out prior to joining the organization and on an ongoing basis taking into consideration applicable laws, regulations and ethics and be proportional to the business requirements, the classification of the information to be accessed and the perceived risks.",
        domain=DOMAIN_PEOPLE,
        objective="To ensure personnel are suitable and trustworthy.",
        attributes=["preventive"],
        nist_mappings=["PS-3"],
        soc2_mappings=["CC1.4"],
    ),
    "A.6.2": ISO27001Control(
        id="A.6.2",
        title="Terms and conditions of employment",
        description="The employment contractual agreements shall state the personnel's and the organization's responsibilities for information security.",
        domain=DOMAIN_PEOPLE,
        objective="To ensure personnel understand their information security responsibilities.",
        attributes=["preventive"],
        nist_mappings=["PS-6", "PL-4"],
        soc2_mappings=["CC1.4"],
    ),
    "A.6.3": ISO27001Control(
        id="A.6.3",
        title="Information security awareness, education and training",
        description="Personnel of the organization and relevant interested parties shall receive appropriate information security awareness, education and training and regular updates of the organization's information security policy, topic-specific policies and procedures, as relevant for their job function.",
        domain=DOMAIN_PEOPLE,
        objective="To ensure personnel are aware of and fulfill their information security responsibilities.",
        attributes=["preventive"],
        nist_mappings=["AT-1", "AT-2", "AT-3"],
        soc2_mappings=["CC1.4", "CC2.2"],
    ),
    "A.6.4": ISO27001Control(
        id="A.6.4",
        title="Disciplinary process",
        description="A disciplinary process shall be formalized and communicated to take actions against personnel and other relevant interested parties who have committed an information security policy violation.",
        domain=DOMAIN_PEOPLE,
        objective="To ensure proper handling of information security policy violations.",
        attributes=["corrective"],
        nist_mappings=["PS-8"],
        soc2_mappings=["CC1.5"],
    ),
    "A.6.5": ISO27001Control(
        id="A.6.5",
        title="Responsibilities after termination or change of employment",
        description="Information security responsibilities and duties that remain valid after termination or change of employment shall be defined, enforced and communicated to relevant personnel and other interested parties.",
        domain=DOMAIN_PEOPLE,
        objective="To protect the organization's interests when personnel leave.",
        attributes=["preventive"],
        nist_mappings=["PS-4", "PS-5"],
        soc2_mappings=["CC6.3"],
    ),
    "A.6.6": ISO27001Control(
        id="A.6.6",
        title="Confidentiality or non-disclosure agreements",
        description="Confidentiality or non-disclosure agreements reflecting the organization's needs for the protection of information shall be identified, documented, regularly reviewed and signed by personnel and other relevant interested parties.",
        domain=DOMAIN_PEOPLE,
        objective="To ensure confidentiality of information.",
        attributes=["preventive"],
        nist_mappings=["PS-6"],
        soc2_mappings=["CC1.4"],
    ),
    "A.6.7": ISO27001Control(
        id="A.6.7",
        title="Remote working",
        description="Security measures shall be implemented when personnel are working remotely to protect information accessed, processed or stored outside the organization's premises.",
        domain=DOMAIN_PEOPLE,
        objective="To ensure security of remote working.",
        attributes=["preventive"],
        nist_mappings=["AC-17", "AC-19"],
        soc2_mappings=["CC6.6"],
    ),
    "A.6.8": ISO27001Control(
        id="A.6.8",
        title="Information security event reporting",
        description="The organization shall provide a mechanism for personnel to report observed or suspected information security events through appropriate channels in a timely manner.",
        domain=DOMAIN_PEOPLE,
        objective="To support timely reporting of information security events.",
        attributes=["detective"],
        nist_mappings=["IR-6", "IR-7"],
        soc2_mappings=["CC7.3"],
    ),
    # =========================================================================
    # A.7 Physical Controls
    # =========================================================================
    "A.7.1": ISO27001Control(
        id="A.7.1",
        title="Physical security perimeters",
        description="Security perimeters shall be defined and used to protect areas that contain information and other associated assets.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent unauthorized physical access.",
        attributes=["preventive"],
        nist_mappings=["PE-1", "PE-3"],
        soc2_mappings=["CC6.4"],
    ),
    "A.7.2": ISO27001Control(
        id="A.7.2",
        title="Physical entry",
        description="Secure areas shall be protected by appropriate entry controls and access points.",
        domain=DOMAIN_PHYSICAL,
        objective="To ensure only authorized access to secure areas.",
        attributes=["preventive"],
        nist_mappings=["PE-2", "PE-3"],
        soc2_mappings=["CC6.4"],
    ),
    "A.7.3": ISO27001Control(
        id="A.7.3",
        title="Securing offices, rooms and facilities",
        description="Physical security for offices, rooms and facilities shall be designed and implemented.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent unauthorized access to offices, rooms and facilities.",
        attributes=["preventive"],
        nist_mappings=["PE-3", "PE-5"],
        soc2_mappings=["CC6.4"],
    ),
    "A.7.4": ISO27001Control(
        id="A.7.4",
        title="Physical security monitoring",
        description="Premises shall be continuously monitored for unauthorized physical access.",
        domain=DOMAIN_PHYSICAL,
        objective="To detect unauthorized physical access.",
        attributes=["detective"],
        nist_mappings=["PE-6", "PE-8"],
        soc2_mappings=["CC6.4"],
    ),
    "A.7.5": ISO27001Control(
        id="A.7.5",
        title="Protecting against physical and environmental threats",
        description="Protection against physical and environmental threats, such as natural disasters and other intentional or unintentional physical threats to infrastructure shall be designed and implemented.",
        domain=DOMAIN_PHYSICAL,
        objective="To protect against physical and environmental threats.",
        attributes=["preventive"],
        nist_mappings=["PE-9", "PE-10", "PE-11"],
        soc2_mappings=["A1.1"],
    ),
    "A.7.6": ISO27001Control(
        id="A.7.6",
        title="Working in secure areas",
        description="Security measures for working in secure areas shall be designed and implemented.",
        domain=DOMAIN_PHYSICAL,
        objective="To protect information in secure areas.",
        attributes=["preventive"],
        nist_mappings=["PE-3"],
        soc2_mappings=["CC6.4"],
    ),
    "A.7.7": ISO27001Control(
        id="A.7.7",
        title="Clear desk and clear screen",
        description="Clear desk rules for papers and removable storage media and clear screen rules for information processing facilities shall be defined and appropriately enforced.",
        domain=DOMAIN_PHYSICAL,
        objective="To reduce the risk of unauthorized access.",
        attributes=["preventive"],
        nist_mappings=["MP-4", "AC-11"],
        soc2_mappings=["CC6.1"],
    ),
    "A.7.8": ISO27001Control(
        id="A.7.8",
        title="Equipment siting and protection",
        description="Equipment shall be sited securely and protected.",
        domain=DOMAIN_PHYSICAL,
        objective="To reduce the risk of physical and environmental threats.",
        attributes=["preventive"],
        nist_mappings=["PE-18"],
        soc2_mappings=["A1.1"],
    ),
    "A.7.9": ISO27001Control(
        id="A.7.9",
        title="Security of assets off-premises",
        description="Off-site assets shall be protected.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent loss, damage, theft or compromise of off-site assets.",
        attributes=["preventive"],
        nist_mappings=["PE-17", "MP-5"],
        soc2_mappings=["CC6.7"],
    ),
    "A.7.10": ISO27001Control(
        id="A.7.10",
        title="Storage media",
        description="Storage media shall be managed through their lifecycle of acquisition, use, transportation and disposal in accordance with the organization's classification scheme and handling requirements.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent unauthorized disclosure, modification, removal or destruction of information stored on storage media.",
        attributes=["preventive"],
        nist_mappings=["MP-2", "MP-4", "MP-6"],
        soc2_mappings=["CC6.5"],
    ),
    "A.7.11": ISO27001Control(
        id="A.7.11",
        title="Supporting utilities",
        description="Information processing facilities shall be protected from power failures and other disruptions caused by failures in supporting utilities.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent loss, damage or compromise of information processing facilities.",
        attributes=["preventive"],
        nist_mappings=["PE-9", "PE-10", "PE-11"],
        soc2_mappings=["A1.1"],
    ),
    "A.7.12": ISO27001Control(
        id="A.7.12",
        title="Cabling security",
        description="Cables carrying power, data or supporting information services shall be protected from interception, interference or damage.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent interception, interference or damage to cables.",
        attributes=["preventive"],
        nist_mappings=["PE-4", "PE-9"],
        soc2_mappings=["CC6.4"],
    ),
    "A.7.13": ISO27001Control(
        id="A.7.13",
        title="Equipment maintenance",
        description="Equipment shall be maintained correctly to ensure availability, integrity and confidentiality of information.",
        domain=DOMAIN_PHYSICAL,
        objective="To ensure correct maintenance of equipment.",
        attributes=["preventive"],
        nist_mappings=["MA-2", "MA-4"],
        soc2_mappings=["A1.1"],
    ),
    "A.7.14": ISO27001Control(
        id="A.7.14",
        title="Secure disposal or re-use of equipment",
        description="Items of equipment containing storage media shall be verified to ensure that any sensitive data and licensed software has been removed or securely overwritten prior to disposal or re-use.",
        domain=DOMAIN_PHYSICAL,
        objective="To prevent leakage of information from equipment.",
        attributes=["preventive"],
        nist_mappings=["MP-6"],
        soc2_mappings=["CC6.5"],
    ),
    # =========================================================================
    # A.8 Technological Controls
    # =========================================================================
    "A.8.1": ISO27001Control(
        id="A.8.1",
        title="User endpoint devices",
        description="Information stored on, processed by or accessible via user endpoint devices shall be protected.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To protect information on user endpoint devices.",
        attributes=["preventive"],
        nist_mappings=["SC-7", "AC-19"],
        soc2_mappings=["CC6.1", "CC6.6"],
    ),
    "A.8.2": ISO27001Control(
        id="A.8.2",
        title="Privileged access rights",
        description="The allocation and use of privileged access rights shall be restricted and managed.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure appropriate authorization of privileged access.",
        attributes=["preventive"],
        nist_mappings=["AC-2", "AC-6"],
        soc2_mappings=["CC6.1", "CC6.3"],
    ),
    "A.8.3": ISO27001Control(
        id="A.8.3",
        title="Information access restriction",
        description="Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure authorized access to information.",
        attributes=["preventive"],
        nist_mappings=["AC-3", "AC-4"],
        soc2_mappings=["CC6.1"],
    ),
    "A.8.4": ISO27001Control(
        id="A.8.4",
        title="Access to source code",
        description="Read and write access to source code, development tools and software libraries shall be appropriately managed.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To prevent unauthorized access to source code.",
        attributes=["preventive"],
        nist_mappings=["CM-5", "AC-3"],
        soc2_mappings=["CC6.1", "CC8.1"],
    ),
    "A.8.5": ISO27001Control(
        id="A.8.5",
        title="Secure authentication",
        description="Secure authentication technologies and procedures shall be implemented based on information access restrictions and the topic-specific policy on access control.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure secure authentication.",
        attributes=["preventive"],
        nist_mappings=["IA-2", "IA-5", "IA-8"],
        soc2_mappings=["CC6.1"],
    ),
    "A.8.6": ISO27001Control(
        id="A.8.6",
        title="Capacity management",
        description="The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure required system performance.",
        attributes=["preventive"],
        nist_mappings=["CP-2", "SA-17"],
        soc2_mappings=["A1.1"],
    ),
    "A.8.7": ISO27001Control(
        id="A.8.7",
        title="Protection against malware",
        description="Protection against malware shall be implemented and supported by appropriate user awareness.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To protect against malware.",
        attributes=["preventive", "detective"],
        nist_mappings=["SI-3", "SI-8"],
        soc2_mappings=["CC6.8"],
    ),
    "A.8.8": ISO27001Control(
        id="A.8.8",
        title="Management of technical vulnerabilities",
        description="Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated and appropriate measures shall be taken.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To prevent exploitation of technical vulnerabilities.",
        attributes=["preventive"],
        nist_mappings=["RA-5", "SI-2"],
        soc2_mappings=["CC7.1"],
    ),
    "A.8.9": ISO27001Control(
        id="A.8.9",
        title="Configuration management",
        description="Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure correct and secure configuration.",
        attributes=["preventive"],
        nist_mappings=["CM-2", "CM-6", "CM-7"],
        soc2_mappings=["CC6.1", "CC7.1"],
    ),
    "A.8.10": ISO27001Control(
        id="A.8.10",
        title="Information deletion",
        description="Information stored in information systems, devices or in any other storage media shall be deleted when no longer required.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To prevent unnecessary exposure of sensitive information.",
        attributes=["preventive"],
        nist_mappings=["MP-6", "SI-12"],
        soc2_mappings=["CC6.5", "P4.2"],
    ),
    "A.8.11": ISO27001Control(
        id="A.8.11",
        title="Data masking",
        description="Data masking shall be used in accordance with the organization's topic-specific policy on access control and other related topic-specific policies, and business requirements, taking applicable legislation into consideration.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To protect sensitive information.",
        attributes=["preventive"],
        nist_mappings=["SC-28", "MP-6"],
        soc2_mappings=["CC6.1", "P6.1"],
    ),
    "A.8.12": ISO27001Control(
        id="A.8.12",
        title="Data leakage prevention",
        description="Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To detect and prevent unauthorized disclosure of information.",
        attributes=["preventive", "detective"],
        nist_mappings=["AC-4", "SC-7"],
        soc2_mappings=["CC6.6", "CC6.7"],
    ),
    "A.8.13": ISO27001Control(
        id="A.8.13",
        title="Information backup",
        description="Backup copies of information, software and systems shall be maintained and regularly tested in accordance with the agreed topic-specific policy on backup.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To protect against loss of data.",
        attributes=["preventive"],
        nist_mappings=["CP-9", "CP-10"],
        soc2_mappings=["A1.2"],
    ),
    "A.8.14": ISO27001Control(
        id="A.8.14",
        title="Redundancy of information processing facilities",
        description="Information processing facilities shall be implemented with redundancy sufficient to meet availability requirements.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure availability of information processing facilities.",
        attributes=["preventive"],
        nist_mappings=["CP-7", "CP-8"],
        soc2_mappings=["A1.2"],
    ),
    "A.8.15": ISO27001Control(
        id="A.8.15",
        title="Logging",
        description="Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To record events for evidence and analysis.",
        attributes=["detective"],
        nist_mappings=["AU-2", "AU-3", "AU-6"],
        soc2_mappings=["CC7.2"],
    ),
    "A.8.16": ISO27001Control(
        id="A.8.16",
        title="Monitoring activities",
        description="Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To detect anomalous behaviour and potential incidents.",
        attributes=["detective"],
        nist_mappings=["SI-4", "AU-6"],
        soc2_mappings=["CC7.2"],
    ),
    "A.8.17": ISO27001Control(
        id="A.8.17",
        title="Clock synchronization",
        description="The clocks of information processing systems used by the organization shall be synchronized to approved time sources.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To support the accuracy of logs and records.",
        attributes=["preventive"],
        nist_mappings=["AU-8"],
        soc2_mappings=["CC7.2"],
    ),
    "A.8.18": ISO27001Control(
        id="A.8.18",
        title="Use of privileged utility programs",
        description="The use of utility programs that might be capable of overriding system and application controls shall be restricted and tightly controlled.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To prevent unauthorized use of utility programs.",
        attributes=["preventive"],
        nist_mappings=["AC-6", "CM-7"],
        soc2_mappings=["CC6.1"],
    ),
    "A.8.19": ISO27001Control(
        id="A.8.19",
        title="Installation of software on operational systems",
        description="Procedures and measures shall be implemented to securely manage software installation on operational systems.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure secure software installation.",
        attributes=["preventive"],
        nist_mappings=["CM-5", "CM-11"],
        soc2_mappings=["CC6.1", "CC8.1"],
    ),
    "A.8.20": ISO27001Control(
        id="A.8.20",
        title="Networks security",
        description="Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To protect information in networks.",
        attributes=["preventive"],
        nist_mappings=["SC-7", "SC-8"],
        soc2_mappings=["CC6.6"],
    ),
    "A.8.21": ISO27001Control(
        id="A.8.21",
        title="Security of network services",
        description="Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure security of network services.",
        attributes=["preventive"],
        nist_mappings=["SC-7", "SC-8"],
        soc2_mappings=["CC6.6", "CC6.7"],
    ),
    "A.8.22": ISO27001Control(
        id="A.8.22",
        title="Segregation of networks",
        description="Groups of information services, users and information systems shall be segregated in the organization's networks.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To control information flow within the network.",
        attributes=["preventive"],
        nist_mappings=["SC-7", "AC-4"],
        soc2_mappings=["CC6.6"],
    ),
    "A.8.23": ISO27001Control(
        id="A.8.23",
        title="Web filtering",
        description="Access to external websites shall be managed to reduce exposure to malicious content.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To protect systems from malicious web content.",
        attributes=["preventive"],
        nist_mappings=["SC-7", "SI-3"],
        soc2_mappings=["CC6.6", "CC6.8"],
    ),
    "A.8.24": ISO27001Control(
        id="A.8.24",
        title="Use of cryptography",
        description="Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure proper and effective use of cryptography.",
        attributes=["preventive"],
        nist_mappings=["SC-8", "SC-12", "SC-13"],
        soc2_mappings=["CC6.1", "CC6.7"],
    ),
    "A.8.25": ISO27001Control(
        id="A.8.25",
        title="Secure development life cycle",
        description="Rules for the secure development of software and systems shall be established and applied.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure information security is designed and implemented within the development lifecycle.",
        attributes=["preventive"],
        nist_mappings=["SA-3", "SA-15"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.26": ISO27001Control(
        id="A.8.26",
        title="Application security requirements",
        description="Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure information security is addressed in application development.",
        attributes=["preventive"],
        nist_mappings=["SA-4", "SA-8"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.27": ISO27001Control(
        id="A.8.27",
        title="Secure system architecture and engineering principles",
        description="Principles for engineering secure systems shall be established, documented, maintained and applied to any information system development activities.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure information security is designed into systems.",
        attributes=["preventive"],
        nist_mappings=["SA-8", "SA-17"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.28": ISO27001Control(
        id="A.8.28",
        title="Secure coding",
        description="Secure coding principles shall be applied to software development.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure secure software is developed.",
        attributes=["preventive"],
        nist_mappings=["SA-11", "SA-15"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.29": ISO27001Control(
        id="A.8.29",
        title="Security testing in development and acceptance",
        description="Security testing processes shall be defined and implemented in the development lifecycle.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To validate that information security requirements have been met.",
        attributes=["detective"],
        nist_mappings=["SA-11", "CA-2"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.30": ISO27001Control(
        id="A.8.30",
        title="Outsourced development",
        description="The organization shall direct, monitor and review the activities related to outsourced system development.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure information security in outsourced development.",
        attributes=["preventive"],
        nist_mappings=["SA-9", "SA-11"],
        soc2_mappings=["CC9.2"],
    ),
    "A.8.31": ISO27001Control(
        id="A.8.31",
        title="Separation of development, test and production environments",
        description="Development, testing and production environments shall be separated and secured.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To reduce risks to the production environment.",
        attributes=["preventive"],
        nist_mappings=["CM-4", "SA-11"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.32": ISO27001Control(
        id="A.8.32",
        title="Change management",
        description="Changes to information processing facilities and information systems shall be subject to change management procedures.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure changes are properly managed.",
        attributes=["preventive"],
        nist_mappings=["CM-3", "CM-4"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.33": ISO27001Control(
        id="A.8.33",
        title="Test information",
        description="Test information shall be appropriately selected, protected and managed.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To ensure confidentiality of test information.",
        attributes=["preventive"],
        nist_mappings=["SA-11"],
        soc2_mappings=["CC8.1"],
    ),
    "A.8.34": ISO27001Control(
        id="A.8.34",
        title="Protection of information systems during audit testing",
        description="Audit tests and other assurance activities involving assessment of operational systems shall be planned and agreed between the tester and appropriate management.",
        domain=DOMAIN_TECHNOLOGICAL,
        objective="To minimize the impact of audit activities on operational systems.",
        attributes=["preventive"],
        nist_mappings=["CA-2", "AU-12"],
        soc2_mappings=["CC4.1"],
    ),
}


# =============================================================================
# AWS Compliance Checks for ISO 27001
# =============================================================================


def get_iso_27001_aws_checks() -> list[CheckDefinition]:
    """
    Get AWS compliance checks mapped to ISO 27001 controls.

    Returns:
        List of CheckDefinition objects for AWS resources.
    """
    return [
        # ---------------------------------------------------------------------------
        # A.5.15/A.5.18: Access Control / Access Rights
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a5-15-1",
            title="IAM users should have MFA enabled",
            description="Multi-factor authentication adds an extra layer of protection for user accounts.",
            severity="high",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.MFADevices",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable MFA for all IAM users.",
            frameworks={"iso-27001": ["A.5.15", "A.5.17", "A.8.5"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a5-15-2",
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
            frameworks={"iso-27001": ["A.5.15", "A.5.17"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-2-1",
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
            frameworks={"iso-27001": ["A.8.2", "A.5.18"]},
        ),
        # ---------------------------------------------------------------------------
        # A.8.15/A.8.16: Logging / Monitoring Activities
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a8-15-1",
            title="CloudTrail should be enabled and logging",
            description="CloudTrail provides audit logs for API calls across AWS services.",
            severity="high",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IsLogging",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable CloudTrail logging.",
            frameworks={"iso-27001": ["A.8.15", "A.5.28"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-15-2",
            title="CloudTrail should be multi-region",
            description="Multi-region trails capture API activity across all AWS regions.",
            severity="high",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IsMultiRegionTrail",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable multi-region CloudTrail trail.",
            frameworks={"iso-27001": ["A.8.15"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-16-1",
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
            frameworks={"iso-27001": ["A.8.16", "A.5.7"]},
        ),
        # ---------------------------------------------------------------------------
        # A.8.20/A.8.22: Network Security / Segregation of Networks
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a8-20-1",
            title="Security groups should not allow unrestricted SSH access",
            description="Unrestricted SSH access from the internet poses a security risk.",
            severity="high",
            resource_types=["security_group"],
            condition=Condition(
                path="raw_data.AllowsSSHFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict SSH access to specific IP ranges.",
            frameworks={"iso-27001": ["A.8.20", "A.8.22"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-20-2",
            title="Security groups should not allow unrestricted RDP access",
            description="Unrestricted RDP access from the internet poses a security risk.",
            severity="high",
            resource_types=["security_group"],
            condition=Condition(
                path="raw_data.AllowsRDPFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict RDP access to specific IP ranges.",
            frameworks={"iso-27001": ["A.8.20", "A.8.22"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-22-1",
            title="VPCs should have flow logs enabled",
            description="VPC flow logs capture information about IP traffic for security analysis.",
            severity="medium",
            resource_types=["vpc"],
            condition=Condition(
                path="raw_data.FlowLogsEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable VPC flow logs for all VPCs.",
            frameworks={"iso-27001": ["A.8.22", "A.8.15"]},
        ),
        # ---------------------------------------------------------------------------
        # A.8.24: Use of Cryptography
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a8-24-1",
            title="S3 buckets should have server-side encryption enabled",
            description="Server-side encryption protects data at rest in S3 buckets.",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.ServerSideEncryptionEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable default encryption on S3 buckets.",
            frameworks={"iso-27001": ["A.8.24", "A.5.33"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-24-2",
            title="EBS volumes should be encrypted",
            description="EBS encryption protects data at rest on EC2 volumes.",
            severity="high",
            resource_types=["ebs_volume"],
            condition=Condition(
                path="raw_data.Encrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for EBS volumes.",
            frameworks={"iso-27001": ["A.8.24"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-24-3",
            title="RDS instances should be encrypted",
            description="RDS encryption protects data at rest in databases.",
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.StorageEncrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for RDS instances.",
            frameworks={"iso-27001": ["A.8.24"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-24-4",
            title="KMS keys should have automatic rotation enabled",
            description="Key rotation limits the amount of data encrypted with a single key.",
            severity="medium",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.KeyRotationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable automatic key rotation for KMS keys.",
            frameworks={"iso-27001": ["A.8.24"]},
        ),
        # ---------------------------------------------------------------------------
        # A.8.9: Configuration Management
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a8-9-1",
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
            frameworks={"iso-27001": ["A.8.9"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-9-2",
            title="AWS Config should be enabled",
            description="AWS Config tracks resource configuration changes.",
            severity="medium",
            resource_types=["config_recorder"],
            condition=Condition(
                path="raw_data.Recording",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable AWS Config in all regions.",
            frameworks={"iso-27001": ["A.8.9", "A.5.9"]},
        ),
        # ---------------------------------------------------------------------------
        # A.8.13: Information Backup
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a8-13-1",
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
            frameworks={"iso-27001": ["A.8.13", "A.5.33"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a8-13-2",
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
            frameworks={"iso-27001": ["A.8.13"]},
        ),
        # ---------------------------------------------------------------------------
        # A.8.14: Redundancy of Information Processing Facilities
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a8-14-1",
            title="RDS instances should be Multi-AZ",
            description="Multi-AZ provides high availability for database instances.",
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.MultiAZ",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Multi-AZ for RDS instances.",
            frameworks={"iso-27001": ["A.8.14", "A.5.30"]},
        ),
        # ---------------------------------------------------------------------------
        # A.5.33: Protection of Records
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="iso-27001-aws-a5-33-1",
            title="CloudTrail logs should be encrypted",
            description="Encrypting CloudTrail logs protects sensitive audit information.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.KMSKeyId",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable KMS encryption for CloudTrail logs.",
            frameworks={"iso-27001": ["A.5.33", "A.8.24"]},
        ),
        CheckDefinition(
            id="iso-27001-aws-a5-33-2",
            title="CloudTrail log file validation should be enabled",
            description="Log file validation ensures audit logs have not been tampered with.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.LogFileValidationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable log file validation for CloudTrail.",
            frameworks={"iso-27001": ["A.5.33", "A.5.28"]},
        ),
    ]


# =============================================================================
# Framework Factory Functions
# =============================================================================


def create_iso_27001_evaluator() -> Evaluator:
    """
    Create an evaluator pre-configured with ISO 27001 checks.

    Returns:
        Evaluator configured with ISO 27001 checks.
    """
    evaluator = Evaluator()

    for check in get_iso_27001_aws_checks():
        evaluator.register_check(check)

    logger.info(
        f"Created ISO 27001 evaluator with {len(evaluator.list_checks())} checks"
    )
    return evaluator


def get_iso_27001_framework() -> ISO27001Framework:
    """
    Get the ISO 27001:2022 framework with controls and check mappings.

    Returns:
        ISO27001Framework with controls and check mappings.
    """
    framework = ISO27001Framework(
        version=ISO_27001_VERSION,
        controls=ISO_27001_CONTROLS,
    )

    # Build check mappings from all checks
    all_checks = get_iso_27001_aws_checks()

    for check in all_checks:
        if "iso-27001" in check.frameworks:
            for control_id in check.frameworks["iso-27001"]:
                if control_id not in framework.check_mappings:
                    framework.check_mappings[control_id] = []
                framework.check_mappings[control_id].append(check.id)

    logger.info(
        f"Built ISO 27001 framework with {len(framework.controls)} controls, "
        f"{len(framework.check_mappings)} mapped to checks"
    )
    return framework


def get_controls_by_domain(domain: str) -> list[ISO27001Control]:
    """
    Get all ISO 27001 controls in a specific domain.

    Args:
        domain: Domain identifier (A.5, A.6, A.7, A.8).

    Returns:
        List of controls in the specified domain.
    """
    return [c for c in ISO_27001_CONTROLS.values() if c.domain == domain]


def get_control_count_by_domain() -> dict[str, int]:
    """
    Get the count of controls in each domain.

    Returns:
        Dictionary mapping domain to control count.
    """
    counts: dict[str, int] = {}
    for control in ISO_27001_CONTROLS.values():
        counts[control.domain] = counts.get(control.domain, 0) + 1
    return counts
