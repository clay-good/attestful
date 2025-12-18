"""
SOC 2 Trust Services Criteria control definitions.

Provides control definitions for all Trust Services Categories:
- Security (Common Criteria CC1-CC9) - Mandatory
- Availability (A1) - Optional
- Processing Integrity (PI1) - Optional
- Confidentiality (C1) - Optional
- Privacy (P1-P8) - Optional

Based on AICPA 2017 Trust Services Criteria.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Framework Constants
# =============================================================================

SOC2_FRAMEWORK_ID = "soc2"
SOC2_VERSION = "2017"  # AICPA Trust Services Criteria version

# Trust Services Categories
TSC_SECURITY = "security"
TSC_AVAILABILITY = "availability"
TSC_PROCESSING_INTEGRITY = "processing_integrity"
TSC_CONFIDENTIALITY = "confidentiality"
TSC_PRIVACY = "privacy"

# Security Common Criteria (CC) Groups
CC6_LOGICAL_PHYSICAL_ACCESS = "CC6"
CC7_SYSTEM_OPERATIONS = "CC7"
CC8_CHANGE_MANAGEMENT = "CC8"
CC9_RISK_MITIGATION = "CC9"

# Category metadata
CATEGORY_METADATA = {
    TSC_SECURITY: {
        "name": "Security (Common Criteria)",
        "description": "Protection of information and systems against unauthorized access, use, or modification",
        "mandatory": True,
    },
    TSC_AVAILABILITY: {
        "name": "Availability",
        "description": "Information and systems are available for operation and use as committed or agreed",
        "mandatory": False,
    },
    TSC_PROCESSING_INTEGRITY: {
        "name": "Processing Integrity",
        "description": "System processing is complete, valid, accurate, timely, and authorized",
        "mandatory": False,
    },
    TSC_CONFIDENTIALITY: {
        "name": "Confidentiality",
        "description": "Information designated as confidential is protected as committed or agreed",
        "mandatory": False,
    },
    TSC_PRIVACY: {
        "name": "Privacy",
        "description": "Personal information is collected, used, retained, disclosed, and disposed of in conformity with commitments",
        "mandatory": False,
    },
}


@dataclass
class SOC2Control:
    """
    A SOC 2 Trust Services Criterion control.

    Attributes:
        id: Control identifier (e.g., "CC6.1").
        title: Short title.
        description: Full description from TSC.
        category: Trust Services Category.
        points_of_focus: AICPA points of focus for this criterion.
        related_criteria: Other related TSC criteria.
    """

    id: str
    title: str
    description: str
    category: str = TSC_SECURITY
    points_of_focus: list[str] = field(default_factory=list)
    related_criteria: list[str] = field(default_factory=list)


@dataclass
class SOC2Framework:
    """
    SOC 2 compliance framework definition.

    Contains all Trust Services Criteria controls and their mappings
    to automated checks.
    """

    version: str = SOC2_VERSION
    controls: dict[str, SOC2Control] = field(default_factory=dict)
    check_mappings: dict[str, list[str]] = field(default_factory=dict)

    def get_control(self, control_id: str) -> SOC2Control | None:
        """Get a control by ID."""
        return self.controls.get(control_id)

    def get_checks_for_control(self, control_id: str) -> list[str]:
        """Get check IDs mapped to a control."""
        return self.check_mappings.get(control_id, [])

    def get_controls_by_category(self, category: str) -> list[SOC2Control]:
        """Get all controls in a category."""
        return [c for c in self.controls.values() if c.category == category]


# =============================================================================
# Trust Services Criteria Control Definitions
# =============================================================================

SOC2_CONTROLS: dict[str, SOC2Control] = {
    # =========================================================================
    # CC1 - Control Environment (COSO Principles 1-5)
    # =========================================================================
    "CC1.1": SOC2Control(
        id="CC1.1",
        title="Demonstrates Commitment to Integrity and Ethical Values",
        description=(
            "The entity demonstrates a commitment to integrity and ethical values."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Sets the Tone at the Top",
            "Establishes Standards of Conduct",
            "Evaluates Adherence to Standards of Conduct",
            "Addresses Deviations in a Timely Manner",
        ],
    ),
    "CC1.2": SOC2Control(
        id="CC1.2",
        title="Exercises Oversight Responsibility",
        description=(
            "The board of directors demonstrates independence from management and "
            "exercises oversight of the development and performance of internal control."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Establishes Oversight Responsibilities",
            "Applies Relevant Expertise",
            "Operates Independently",
            "Provides Oversight for the System of Internal Control",
        ],
    ),
    "CC1.3": SOC2Control(
        id="CC1.3",
        title="Establishes Structure, Authority, and Responsibility",
        description=(
            "Management establishes, with board oversight, structures, reporting lines, "
            "and appropriate authorities and responsibilities in the pursuit of objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Considers All Structures of the Entity",
            "Establishes Reporting Lines",
            "Defines, Assigns, and Limits Authorities and Responsibilities",
        ],
    ),
    "CC1.4": SOC2Control(
        id="CC1.4",
        title="Demonstrates Commitment to Competence",
        description=(
            "The entity demonstrates a commitment to attract, develop, and retain "
            "competent individuals in alignment with objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Establishes Policies and Practices",
            "Evaluates Competence and Addresses Shortcomings",
            "Attracts, Develops, and Retains Individuals",
            "Plans and Prepares for Succession",
        ],
    ),
    "CC1.5": SOC2Control(
        id="CC1.5",
        title="Enforces Accountability",
        description=(
            "The entity holds individuals accountable for their internal control "
            "responsibilities in the pursuit of objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Enforces Accountability Through Structures, Authorities, and Responsibilities",
            "Establishes Performance Measures, Incentives, and Rewards",
            "Evaluates Performance Measures, Incentives, and Rewards for Ongoing Relevance",
            "Considers Excessive Pressures",
            "Evaluates Performance and Rewards or Disciplines Individuals",
        ],
    ),

    # =========================================================================
    # CC2 - Communication and Information (COSO Principles 13-15)
    # =========================================================================
    "CC2.1": SOC2Control(
        id="CC2.1",
        title="Uses Relevant Information",
        description=(
            "The entity obtains or generates and uses relevant, quality information "
            "to support the functioning of internal control."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Identifies Information Requirements",
            "Captures Internal and External Sources of Data",
            "Processes Relevant Data Into Information",
            "Maintains Quality Throughout Processing",
            "Considers Costs and Benefits",
        ],
    ),
    "CC2.2": SOC2Control(
        id="CC2.2",
        title="Communicates Internally",
        description=(
            "The entity internally communicates information, including objectives "
            "and responsibilities for internal control, necessary to support "
            "the functioning of internal control."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Communicates Internal Control Information",
            "Communicates With the Board of Directors",
            "Provides Separate Communication Lines",
            "Selects Relevant Method of Communication",
        ],
    ),
    "CC2.3": SOC2Control(
        id="CC2.3",
        title="Communicates Externally",
        description=(
            "The entity communicates with external parties regarding matters "
            "affecting the functioning of internal control."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Communicates to External Parties",
            "Enables Inbound Communications",
            "Communicates With the Board of Directors",
            "Provides Separate Communication Lines",
            "Selects Relevant Method of Communication",
        ],
    ),

    # =========================================================================
    # CC3 - Risk Assessment (COSO Principles 6-9)
    # =========================================================================
    "CC3.1": SOC2Control(
        id="CC3.1",
        title="Specifies Suitable Objectives",
        description=(
            "The entity specifies objectives with sufficient clarity to enable "
            "the identification and assessment of risks relating to objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Reflects Management's Choices",
            "Considers Tolerances for Risk",
            "Includes Operations, Reporting, and Compliance Objectives",
            "Forms a Basis for Committing of Resources",
        ],
    ),
    "CC3.2": SOC2Control(
        id="CC3.2",
        title="Identifies and Analyzes Risk",
        description=(
            "The entity identifies risks to the achievement of its objectives "
            "across the entity and analyzes risks as a basis for determining "
            "how the risks should be managed."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Includes Entity, Subsidiary, Division, Operating Unit, and Functional Levels",
            "Analyzes Internal and External Factors",
            "Involves Appropriate Levels of Management",
            "Estimates Significance of Risks Identified",
            "Determines How to Respond to Risks",
        ],
    ),
    "CC3.3": SOC2Control(
        id="CC3.3",
        title="Assesses Fraud Risk",
        description=(
            "The entity considers the potential for fraud in assessing risks "
            "to the achievement of objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Considers Various Types of Fraud",
            "Assesses Incentives and Pressures",
            "Assesses Opportunities",
            "Assesses Attitudes and Rationalizations",
        ],
    ),
    "CC3.4": SOC2Control(
        id="CC3.4",
        title="Identifies and Analyzes Significant Change",
        description=(
            "The entity identifies and assesses changes that could significantly "
            "impact the system of internal control."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Assesses Changes in the External Environment",
            "Assesses Changes in the Business Model",
            "Assesses Changes in Leadership",
        ],
    ),

    # =========================================================================
    # CC4 - Monitoring Activities (COSO Principles 16-17)
    # =========================================================================
    "CC4.1": SOC2Control(
        id="CC4.1",
        title="Conducts Ongoing and/or Separate Evaluations",
        description=(
            "The entity selects, develops, and performs ongoing and/or separate "
            "evaluations to ascertain whether the components of internal control "
            "are present and functioning."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Considers a Mix of Ongoing and Separate Evaluations",
            "Considers Rate of Change",
            "Establishes Baseline Understanding",
            "Uses Knowledgeable Personnel",
            "Integrates With Business Processes",
            "Adjusts Scope and Frequency",
            "Objectively Evaluates",
        ],
    ),
    "CC4.2": SOC2Control(
        id="CC4.2",
        title="Evaluates and Communicates Deficiencies",
        description=(
            "The entity evaluates and communicates internal control deficiencies "
            "in a timely manner to those parties responsible for taking corrective "
            "action, including senior management and the board of directors."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Assesses Results",
            "Communicates Deficiencies",
            "Monitors Corrective Actions",
        ],
    ),

    # =========================================================================
    # CC5 - Control Activities (COSO Principles 10-12)
    # =========================================================================
    "CC5.1": SOC2Control(
        id="CC5.1",
        title="Selects and Develops Control Activities",
        description=(
            "The entity selects and develops control activities that contribute "
            "to the mitigation of risks to the achievement of objectives to "
            "acceptable levels."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Integrates With Risk Assessment",
            "Considers Entity-Specific Factors",
            "Determines Relevant Business Processes",
            "Evaluates a Mix of Control Activity Types",
            "Considers at What Level Activities Are Applied",
            "Addresses Segregation of Duties",
        ],
    ),
    "CC5.2": SOC2Control(
        id="CC5.2",
        title="Selects and Develops General Controls Over Technology",
        description=(
            "The entity also selects and develops general control activities "
            "over technology to support the achievement of objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Determines Dependency Between the Use of Technology in Business Processes and Technology General Controls",
            "Establishes Relevant Technology Infrastructure Control Activities",
            "Establishes Relevant Security Management Process Control Activities",
            "Establishes Relevant Technology Acquisition, Development, and Maintenance Process Control Activities",
        ],
    ),
    "CC5.3": SOC2Control(
        id="CC5.3",
        title="Deploys Through Policies and Procedures",
        description=(
            "The entity deploys control activities through policies that establish "
            "what is expected and procedures that put policies into action."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Establishes Policies and Procedures to Support Deployment of Management's Directives",
            "Establishes Responsibility and Accountability for Executing Policies and Procedures",
            "Performs in a Timely Manner",
            "Takes Corrective Action",
            "Performs Using Competent Personnel",
            "Reassesses Policies and Procedures",
        ],
    ),

    # =========================================================================
    # CC6 - Logical and Physical Access Controls
    # =========================================================================
    "CC6.1": SOC2Control(
        id="CC6.1",
        title="Logical Access Security Software, Infrastructure, and Architectures",
        description=(
            "The entity implements logical access security software, infrastructure, "
            "and architectures over protected information assets to protect them from "
            "security events to meet the entity's objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Identifies and Manages the Inventory of Information Assets",
            "Restricts Logical Access",
            "Identifies and Authenticates Users",
            "Considers Network Segmentation",
            "Manages Points of Access",
            "Restricts Access to Information Assets",
            "Manages Identification and Authentication",
            "Manages Credentials for Infrastructure and Software",
            "Uses Encryption to Protect Data",
            "Protects Encryption Keys",
        ],
    ),
    "CC6.2": SOC2Control(
        id="CC6.2",
        title="Prior to Issuing System Credentials and Granting System Access",
        description=(
            "Prior to issuing system credentials and granting system access, the entity "
            "registers and authorizes new internal and external users whose access is "
            "administered by the entity."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Controls Access Credentials to Protected Assets",
            "Removes Access to Protected Assets When Appropriate",
            "Reviews Appropriateness of Access Credentials",
        ],
    ),
    "CC6.3": SOC2Control(
        id="CC6.3",
        title="Removes Access to Protected Assets",
        description=(
            "The entity authorizes, modifies, or removes access to data, software, "
            "functions, and other protected information assets based on roles, "
            "responsibilities, or the system design and changes, giving consideration "
            "to the concepts of least privilege and segregation of duties."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Creates or Modifies Access to Protected Information Assets",
            "Removes Access to Protected Information Assets",
            "Uses Role-Based Access Controls",
            "Reviews Access Roles and Rules",
        ],
    ),
    "CC6.4": SOC2Control(
        id="CC6.4",
        title="Restricts Physical Access",
        description=(
            "The entity restricts physical access to facilities and protected "
            "information assets (for example, data center facilities, backup media "
            "storage, and other sensitive locations) to authorized personnel."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Creates or Modifies Physical Access",
            "Removes Physical Access",
            "Reviews Physical Access",
        ],
    ),
    "CC6.5": SOC2Control(
        id="CC6.5",
        title="Disposes of Protected Assets",
        description=(
            "The entity discontinues logical and physical protections over physical "
            "assets only after the ability to read or recover data and software "
            "from those assets has been diminished."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Identifies Data and Software for Disposal",
            "Removes Data and Software from Entity Control",
        ],
    ),
    "CC6.6": SOC2Control(
        id="CC6.6",
        title="Restricts System Access to Authorized Users",
        description=(
            "The entity implements logical access security measures to protect against "
            "threats from sources outside its system boundaries."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Restricts Access",
            "Protects Identification and Authentication Credentials",
            "Requires Additional Authentication or Credentials",
            "Implements Boundary Protection Systems",
        ],
    ),
    "CC6.7": SOC2Control(
        id="CC6.7",
        title="Restricts Data Transmission, Movement, and Removal",
        description=(
            "The entity restricts the transmission, movement, and removal of information "
            "to authorized internal and external users and processes."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Restricts the Ability to Perform Transmission",
            "Uses Encryption Technologies or Secure Communication Channels",
            "Protects Removal Media",
            "Protects Mobile Devices",
        ],
    ),
    "CC6.8": SOC2Control(
        id="CC6.8",
        title="Prevents or Detects Unauthorized or Malicious Software",
        description=(
            "The entity implements controls to prevent or detect and act upon the "
            "introduction of unauthorized or malicious software."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Restricts Application and Software Installation",
            "Detects Unauthorized Changes to Software and Configuration Parameters",
            "Uses a Defined Change Control Process",
            "Uses Antivirus and Anti-Malware Software",
            "Scans Information Assets from Outside the Entity for Malware and Other Unauthorized Software",
        ],
    ),

    # =========================================================================
    # CC7 - System Operations
    # =========================================================================
    "CC7.1": SOC2Control(
        id="CC7.1",
        title="Detects and Monitors Security Events",
        description=(
            "To meet its objectives, the entity uses detection and monitoring procedures "
            "to identify (1) changes to configurations that result in the introduction "
            "of new vulnerabilities, and (2) susceptibilities to newly discovered "
            "vulnerabilities."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Uses Defined Configuration Standards",
            "Monitors Infrastructure and Software",
            "Implements Change-Detection Mechanisms",
            "Detects Unknown or Unauthorized Components",
            "Conducts Vulnerability Scans",
        ],
    ),
    "CC7.2": SOC2Control(
        id="CC7.2",
        title="Monitors System Components",
        description=(
            "The entity monitors system components and the operation of those components "
            "for anomalies that are indicative of malicious acts, natural disasters, "
            "and errors affecting the entity's ability to meet its objectives."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Implements Detection Policies, Procedures, and Tools",
            "Designs Detection Measures",
            "Implements Filters to Analyze Anomalies",
            "Monitors Detection Tools for Effective Operation",
        ],
    ),
    "CC7.3": SOC2Control(
        id="CC7.3",
        title="Evaluates Security Events",
        description=(
            "The entity evaluates security events to determine whether they could "
            "or have resulted in a failure of the entity to meet its objectives "
            "(security incidents)."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Responds to Security Incidents",
            "Communicates and Reviews Detected Security Events",
            "Develops and Implements Procedures to Analyze Security Incidents",
            "Assesses the Impact of Security Incidents",
        ],
    ),
    "CC7.4": SOC2Control(
        id="CC7.4",
        title="Responds to Security Incidents",
        description=(
            "The entity responds to identified security incidents by executing a defined "
            "incident response program to understand, contain, remediate, and communicate "
            "security incidents."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Assigns Roles and Responsibilities",
            "Contains Security Incidents",
            "Mitigates Ongoing Security Incidents",
            "Ends Threats Posed by Security Incidents",
            "Restores Operations",
            "Develops and Implements Communication Protocols",
            "Obtains Understanding of Nature of Incident and Determines Containment Strategy",
            "Remediates Identified Vulnerabilities",
            "Communicates Remediation Activities",
            "Evaluates the Effectiveness of Incident Response",
        ],
    ),
    "CC7.5": SOC2Control(
        id="CC7.5",
        title="Recovers from Security Incidents",
        description=(
            "The entity identifies, develops, and implements activities to recover "
            "from identified security incidents."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Restores the Affected Environment",
            "Communicates Information About the Event",
            "Determines Root Cause of the Event",
            "Implements Changes to Prevent and Detect Recurrences",
        ],
    ),

    # =========================================================================
    # CC8 - Change Management
    # =========================================================================
    "CC8.1": SOC2Control(
        id="CC8.1",
        title="Changes to Infrastructure and Software",
        description=(
            "The entity authorizes, designs, develops or acquires, configures, "
            "documents, tests, approves, and implements changes to infrastructure "
            "and software."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Manages Changes Throughout the System Life Cycle",
            "Authorizes Changes",
            "Designs and Develops Changes",
            "Documents Changes",
            "Tracks System Changes",
            "Configures Software",
            "Tests System Changes",
            "Approves System Changes",
            "Deploys System Changes",
            "Identifies and Evaluates System Changes",
            "Identifies Changes in Infrastructure, Data, Software, and Procedures Required to Remediate Incidents",
        ],
    ),

    # =========================================================================
    # CC9 - Risk Mitigation
    # =========================================================================
    "CC9.1": SOC2Control(
        id="CC9.1",
        title="Identifies and Manages the Risks",
        description=(
            "The entity identifies, selects, and develops risk mitigation activities "
            "for risks arising from potential business disruptions."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Considers Mitigation of Risks of Business Disruption",
            "Considers the Use of Insurance to Mitigate Financial Impact Risks",
        ],
    ),
    "CC9.2": SOC2Control(
        id="CC9.2",
        title="Manages Risks Associated with Vendors and Business Partners",
        description=(
            "The entity assesses and manages risks associated with vendors and "
            "business partners."
        ),
        category=TSC_SECURITY,
        points_of_focus=[
            "Establishes Requirements for Vendor and Business Partner Engagements",
            "Assesses Vendor and Business Partner Risks",
            "Assigns Responsibility and Accountability for Managing Vendors",
            "Establishes Communication Protocols for Vendors and Business Partners",
            "Establishes Exception Handling Procedures from Vendors and Business Partners",
            "Assesses Vendor and Business Partner Performance",
            "Implements Procedures for Addressing Issues Identified During Vendor and Business Partner Assessments",
            "Implements Procedures for Terminating Vendor and Business Partner Relationships",
        ],
    ),

    # =========================================================================
    # A1 - Availability
    # =========================================================================
    "A1.1": SOC2Control(
        id="A1.1",
        title="System Availability Objectives and Commitments",
        description=(
            "The entity maintains, monitors, and evaluates current processing "
            "capacity and use of system components (infrastructure, data, and "
            "software) to manage capacity demand and to enable the implementation "
            "of additional capacity to help meet its objectives."
        ),
        category=TSC_AVAILABILITY,
        points_of_focus=[
            "Measures Current Usage",
            "Forecasts Capacity",
            "Makes Changes Based on Forecasts",
        ],
    ),
    "A1.2": SOC2Control(
        id="A1.2",
        title="Environmental Protections, Software, and Data Recovery",
        description=(
            "The entity authorizes, designs, develops or acquires, implements, "
            "operates, approves, maintains, and monitors environmental protections, "
            "software, data backup processes, and recovery infrastructure to meet "
            "its objectives."
        ),
        category=TSC_AVAILABILITY,
        points_of_focus=[
            "Identifies Environmental Threats",
            "Designs Detection Measures",
            "Implements and Maintains Environmental Protection Mechanisms",
            "Implements Alerts to Analyze Anomalies",
            "Responds to Environmental Threat Events",
            "Communicates and Reviews Detected Environmental Threat Events",
            "Determines Data to Be Backed Up",
            "Performs Data Backup",
            "Addresses Offsite Storage",
            "Implements Alternate Processing Infrastructure",
        ],
    ),
    "A1.3": SOC2Control(
        id="A1.3",
        title="Recovery Testing",
        description=(
            "The entity tests recovery plan procedures supporting system recovery "
            "to meet its objectives."
        ),
        category=TSC_AVAILABILITY,
        points_of_focus=[
            "Implements Business Continuity Plan Testing",
            "Tests Integrity and Completeness of Backup Data",
            "Tests Recovery Plan Procedures",
        ],
    ),

    # =========================================================================
    # PI1 - Processing Integrity
    # =========================================================================
    "PI1.1": SOC2Control(
        id="PI1.1",
        title="Obtains or Generates Relevant, Quality Information",
        description=(
            "The entity obtains or generates relevant, quality information "
            "regarding the inputs to the system."
        ),
        category=TSC_PROCESSING_INTEGRITY,
        points_of_focus=[
            "Defines Characteristics of Processing Inputs",
            "Evaluates Processing Inputs",
        ],
    ),
    "PI1.2": SOC2Control(
        id="PI1.2",
        title="Implements Policies and Procedures Over System Inputs",
        description=(
            "The entity implements policies and procedures over system inputs "
            "to ensure that they are complete, accurate, timely, and authorized."
        ),
        category=TSC_PROCESSING_INTEGRITY,
        points_of_focus=[
            "Defines Processing Activities",
            "Designs and Implements Measures to Identify Processing Errors",
            "Implements Validation Checks",
        ],
    ),
    "PI1.3": SOC2Control(
        id="PI1.3",
        title="Implements Policies and Procedures for Processing",
        description=(
            "The entity implements policies and procedures over processing "
            "activities to ensure that processing is complete, accurate, timely, "
            "and authorized."
        ),
        category=TSC_PROCESSING_INTEGRITY,
        points_of_focus=[
            "Defines Processing Activities",
            "Designs and Implements Measures to Identify Processing Errors",
            "Records System Processing Activities",
        ],
    ),
    "PI1.4": SOC2Control(
        id="PI1.4",
        title="Makes Available or Delivers Output",
        description=(
            "The entity implements policies and procedures to make available or "
            "deliver output completely, accurately, and timely in accordance with "
            "specifications to meet the entity's objectives."
        ),
        category=TSC_PROCESSING_INTEGRITY,
        points_of_focus=[
            "Protects Output",
            "Distributes Output Only to Intended Parties",
            "Distributes Output Completely and Accurately",
            "Creates and Maintains Records of System Output Activities",
        ],
    ),
    "PI1.5": SOC2Control(
        id="PI1.5",
        title="Stores Inputs, Items in Processing, and Outputs",
        description=(
            "The entity implements policies and procedures to store inputs, items "
            "in processing, and outputs completely, accurately, and timely in "
            "accordance with system specifications to meet the entity's objectives."
        ),
        category=TSC_PROCESSING_INTEGRITY,
        points_of_focus=[
            "Protects Stored Items",
            "Archives and Protects System Records",
        ],
    ),

    # =========================================================================
    # C1 - Confidentiality
    # =========================================================================
    "C1.1": SOC2Control(
        id="C1.1",
        title="Identifies and Maintains Confidential Information",
        description=(
            "The entity identifies and maintains confidential information to meet "
            "the entity's objectives related to confidentiality."
        ),
        category=TSC_CONFIDENTIALITY,
        points_of_focus=[
            "Identifies Confidential Information",
            "Determines Appropriate Protection",
        ],
    ),
    "C1.2": SOC2Control(
        id="C1.2",
        title="Disposes of Confidential Information",
        description=(
            "The entity disposes of confidential information to meet the entity's "
            "objectives related to confidentiality."
        ),
        category=TSC_CONFIDENTIALITY,
        points_of_focus=[
            "Identifies Confidential Information for Destruction",
            "Destroys Confidential Information",
        ],
    ),

    # =========================================================================
    # P1-P8 - Privacy
    # =========================================================================
    "P1.1": SOC2Control(
        id="P1.1",
        title="Privacy Notice",
        description=(
            "The entity provides notice to data subjects about its privacy practices "
            "to meet the entity's objectives related to privacy."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Communicates to Data Subjects",
            "Provides Notice to Data Subjects",
        ],
    ),
    "P2.1": SOC2Control(
        id="P2.1",
        title="Choice and Consent",
        description=(
            "The entity communicates choices available regarding the collection, "
            "use, retention, disclosure, and disposal of personal information to "
            "data subjects."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Communicates to Data Subjects",
            "Obtains Consent for Collection",
        ],
    ),
    "P3.1": SOC2Control(
        id="P3.1",
        title="Collection of Personal Information",
        description=(
            "Personal information is collected consistent with the entity's "
            "objectives related to privacy."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Limits Collection of Personal Information",
            "Collects Information by Fair and Lawful Means",
        ],
    ),
    "P3.2": SOC2Control(
        id="P3.2",
        title="Collection From Third Parties",
        description=(
            "For information that is collected from other sources, the entity "
            "collects personal information consistent with the entity's objectives."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Collects Personal Information from Third Parties",
            "Confirms Third Parties Have Obtained Consent",
        ],
    ),
    "P4.1": SOC2Control(
        id="P4.1",
        title="Use of Personal Information",
        description=(
            "The entity limits the use of personal information to the purposes "
            "identified in the entity's objectives related to privacy."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Limits Use of Personal Information",
        ],
    ),
    "P4.2": SOC2Control(
        id="P4.2",
        title="Retention of Personal Information",
        description=(
            "The entity retains personal information consistent with the entity's "
            "objectives related to privacy."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Retains Personal Information",
            "Protects Personal Information",
        ],
    ),
    "P4.3": SOC2Control(
        id="P4.3",
        title="Disposal of Personal Information",
        description=(
            "The entity securely disposes of personal information to meet the "
            "entity's objectives related to privacy."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Captures, Identifies, and Flags Requests for Deletion",
            "Disposes of, Destroys, and Redacts Personal Information",
        ],
    ),
    "P5.1": SOC2Control(
        id="P5.1",
        title="Access to Personal Information",
        description=(
            "The entity grants identified and authenticated data subjects the "
            "ability to access their stored personal information for review and, "
            "upon request, provides physical or electronic copies of that information."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Authenticates Data Subjects' Identity",
            "Permits Data Subjects to Access Their Personal Information",
        ],
    ),
    "P5.2": SOC2Control(
        id="P5.2",
        title="Correction of Personal Information",
        description=(
            "The entity corrects, amends, or appends personal information based "
            "on information provided by data subjects."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Captures, Identifies, and Processes Data Subjects' Correction Requests",
        ],
    ),
    "P6.1": SOC2Control(
        id="P6.1",
        title="Disclosure to Third Parties",
        description=(
            "The entity discloses personal information to third parties with the "
            "explicit consent of data subjects."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Communicates Privacy Obligations to Third Parties",
            "Discloses Personal Information Only When Appropriate",
        ],
    ),
    "P6.2": SOC2Control(
        id="P6.2",
        title="Authorized Disclosure",
        description=(
            "The entity creates and retains a complete, accurate, and timely record "
            "of authorized disclosures of personal information."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Creates and Retains Record of Authorized Disclosures",
        ],
    ),
    "P6.3": SOC2Control(
        id="P6.3",
        title="Unauthorized Disclosure",
        description=(
            "The entity creates and retains a complete, accurate, and timely record "
            "of detected or reported unauthorized disclosures of personal information."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Creates and Retains Record of Unauthorized Disclosures",
        ],
    ),
    "P7.1": SOC2Control(
        id="P7.1",
        title="Quality of Personal Information",
        description=(
            "The entity collects and maintains accurate, up-to-date, complete, "
            "and relevant personal information to meet the entity's objectives."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Ensures Accuracy and Completeness of Personal Information",
        ],
    ),
    "P8.1": SOC2Control(
        id="P8.1",
        title="Inquiry, Complaint, and Dispute Resolution",
        description=(
            "The entity implements a process for receiving, addressing, resolving, "
            "and communicating the resolution of inquiries, complaints, and disputes."
        ),
        category=TSC_PRIVACY,
        points_of_focus=[
            "Addresses Inquiries, Complaints, and Disputes",
            "Documents and Communicates Dispute Resolution",
        ],
    ),
}


# =============================================================================
# Utility Functions
# =============================================================================


def get_control(control_id: str) -> SOC2Control | None:
    """
    Get a SOC 2 control by ID.

    Args:
        control_id: Control ID (e.g., "CC6.1")

    Returns:
        SOC2Control if found, None otherwise
    """
    return SOC2_CONTROLS.get(control_id.upper())


def get_controls_by_category(category: str) -> list[SOC2Control]:
    """
    Get all controls in a Trust Services Category.

    Args:
        category: Category ID (e.g., "security", "availability")

    Returns:
        List of SOC2Control objects
    """
    return [c for c in SOC2_CONTROLS.values() if c.category == category]


def get_all_controls() -> dict[str, SOC2Control]:
    """Get all SOC 2 controls."""
    return SOC2_CONTROLS.copy()


def get_all_categories() -> list[str]:
    """Get all Trust Services Category IDs."""
    return list(CATEGORY_METADATA.keys())


def get_category_metadata(category: str) -> dict | None:
    """Get metadata for a category."""
    return CATEGORY_METADATA.get(category)


def get_control_count_by_category() -> dict[str, int]:
    """Get count of controls by category."""
    counts: dict[str, int] = {}
    for category in CATEGORY_METADATA:
        counts[category] = len(get_controls_by_category(category))
    return counts


__all__ = [
    # Constants
    "SOC2_FRAMEWORK_ID",
    "SOC2_VERSION",
    "TSC_SECURITY",
    "TSC_AVAILABILITY",
    "TSC_PROCESSING_INTEGRITY",
    "TSC_CONFIDENTIALITY",
    "TSC_PRIVACY",
    "CC6_LOGICAL_PHYSICAL_ACCESS",
    "CC7_SYSTEM_OPERATIONS",
    "CC8_CHANGE_MANAGEMENT",
    "CC9_RISK_MITIGATION",
    "CATEGORY_METADATA",
    # Classes
    "SOC2Control",
    "SOC2Framework",
    # Data
    "SOC2_CONTROLS",
    # Functions
    "get_control",
    "get_controls_by_category",
    "get_all_controls",
    "get_all_categories",
    "get_category_metadata",
    "get_control_count_by_category",
]
