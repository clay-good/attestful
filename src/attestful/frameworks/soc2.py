"""
SOC 2 Type II compliance framework for Attestful.

Implements automated compliance checks for SOC 2 Trust Services Criteria,
focusing on the mandatory Security (Common Criteria) category.

SOC 2 Trust Services Categories:
- Security (Common Criteria CC6-CC9) - Mandatory
- Availability (A1) - Optional
- Processing Integrity (PI1) - Optional
- Confidentiality (C1) - Optional
- Privacy (P1-P8) - Optional
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
# SOC 2 Framework Constants
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
    """

    id: str
    title: str
    description: str
    category: str = TSC_SECURITY
    points_of_focus: list[str] = field(default_factory=list)


@dataclass
class SOC2Framework:
    """
    SOC 2 compliance framework definition.

    Contains all Trust Services Criteria controls and their mappings
    to automated checks.
    """

    version: str = SOC2_VERSION
    controls: dict[str, SOC2Control] = field(default_factory=dict)
    check_mappings: dict[str, list[str]] = field(default_factory=dict)  # control_id -> check_ids

    def get_control(self, control_id: str) -> SOC2Control | None:
        """Get a control by ID."""
        return self.controls.get(control_id)

    def get_checks_for_control(self, control_id: str) -> list[str]:
        """Get check IDs mapped to a control."""
        return self.check_mappings.get(control_id, [])


# =============================================================================
# SOC 2 Control Definitions
# =============================================================================

SOC2_CONTROLS = {
    # CC6 - Logical and Physical Access Controls
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
    # CC7 - System Operations
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
    # CC8 - Change Management
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
    # CC9 - Risk Mitigation
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
    # Availability (A1) - Optional
    "A1.1": SOC2Control(
        id="A1.1",
        title="Maintains and Documents Processing Capacity",
        description=(
            "The entity maintains, monitors, and evaluates current processing capacity "
            "and use of system components (infrastructure, data, and software) to manage "
            "capacity demand and to enable the implementation of additional capacity to "
            "help meet its objectives."
        ),
        category=TSC_AVAILABILITY,
    ),
    "A1.2": SOC2Control(
        id="A1.2",
        title="Environmental Protections",
        description=(
            "The entity authorizes, designs, develops or acquires, implements, operates, "
            "approves, maintains, and monitors environmental protections, software, "
            "data backup processes, and recovery infrastructure to meet its objectives."
        ),
        category=TSC_AVAILABILITY,
    ),
    "A1.3": SOC2Control(
        id="A1.3",
        title="Recovery Plan Testing",
        description=(
            "The entity tests recovery plan procedures supporting system recovery to meet "
            "its objectives."
        ),
        category=TSC_AVAILABILITY,
    ),
}


# =============================================================================
# SOC 2 Automated Check Definitions
# =============================================================================


def get_soc2_aws_checks() -> list[CheckDefinition]:
    """
    Get automated SOC 2 checks for AWS resources.

    Returns:
        List of check definitions mapped to SOC 2 Trust Services Criteria.
    """
    return [
        # =====================================================================
        # CC6.1 - Logical Access Security
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.1-mfa-enabled",
            title="IAM User MFA Enabled",
            description=(
                "Ensure all IAM users have multi-factor authentication (MFA) enabled. "
                "MFA adds an additional layer of protection on top of a username and password."
            ),
            severity="critical",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.MFADevices",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation=(
                "Enable MFA for the IAM user:\n"
                "1. Sign in to AWS Management Console\n"
                "2. Navigate to IAM > Users\n"
                "3. Select the user\n"
                "4. Click Security credentials tab\n"
                "5. Enable MFA device"
            ),
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-2"]},
            tags=["authentication", "mfa", "iam"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-password-min-length",
            title="IAM Password Policy Minimum Length",
            description=(
                "Ensure IAM password policy requires a minimum password length of 14 characters. "
                "Strong password policies help prevent brute force attacks."
            ),
            severity="high",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.MinimumPasswordLength",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=14,
            ),
            remediation="Set minimum password length to at least 14 characters in IAM password policy.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-5"]},
            tags=["password", "iam", "authentication"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-password-uppercase",
            title="IAM Password Policy Requires Uppercase",
            description=(
                "Ensure IAM password policy requires at least one uppercase letter. "
                "Password complexity helps prevent dictionary attacks."
            ),
            severity="high",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.RequireUppercaseCharacters",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable uppercase character requirement in IAM password policy.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-5"]},
            tags=["password", "iam", "authentication"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-password-lowercase",
            title="IAM Password Policy Requires Lowercase",
            description=(
                "Ensure IAM password policy requires at least one lowercase letter. "
                "Password complexity helps prevent dictionary attacks."
            ),
            severity="high",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.RequireLowercaseCharacters",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable lowercase character requirement in IAM password policy.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-5"]},
            tags=["password", "iam", "authentication"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-password-numbers",
            title="IAM Password Policy Requires Numbers",
            description=(
                "Ensure IAM password policy requires at least one number. "
                "Password complexity helps prevent dictionary attacks."
            ),
            severity="high",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.RequireNumbers",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable number requirement in IAM password policy.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-5"]},
            tags=["password", "iam", "authentication"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-password-symbols",
            title="IAM Password Policy Requires Symbols",
            description=(
                "Ensure IAM password policy requires at least one symbol. "
                "Password complexity helps prevent dictionary attacks."
            ),
            severity="high",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.RequireSymbols",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable symbol requirement in IAM password policy.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-5"]},
            tags=["password", "iam", "authentication"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-password-expiration",
            title="IAM Password Policy Expiration",
            description=(
                "Ensure IAM password policy enforces password expiration within 90 days. "
                "Regular password rotation reduces the risk of compromised credentials."
            ),
            severity="medium",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.MaxPasswordAge",
                operator=Operator.LESS_THAN_OR_EQUAL,
                value=90,
            ),
            remediation="Set maximum password age to 90 days or less in IAM password policy.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["IA-5"]},
            tags=["password", "iam", "authentication"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-s3-encryption",
            title="S3 Bucket Encryption Enabled",
            description=(
                "Ensure all S3 buckets have server-side encryption enabled. "
                "Encryption protects data at rest from unauthorized access."
            ),
            severity="critical",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Encryption",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation=(
                "Enable default encryption for S3 bucket:\n"
                "1. Open S3 console\n"
                "2. Select bucket\n"
                "3. Go to Properties > Default encryption\n"
                "4. Enable encryption (AES-256 or AWS-KMS)"
            ),
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["encryption", "s3", "data-protection"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-rds-encryption",
            title="RDS Instance Encryption Enabled",
            description=(
                "Ensure RDS instances have encryption at rest enabled. "
                "Encryption protects database data from unauthorized access."
            ),
            severity="critical",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.StorageEncrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption when creating RDS instance (cannot be enabled after creation).",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["encryption", "rds", "data-protection"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-ebs-encryption",
            title="EBS Volume Encryption Enabled",
            description=(
                "Ensure EBS volumes are encrypted to protect data at rest. "
                "Unencrypted volumes expose data to unauthorized access."
            ),
            severity="high",
            resource_types=["ebs_volume"],
            condition=Condition(
                path="raw_data.Encrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation=(
                "Create encrypted snapshot and replace unencrypted volume:\n"
                "1. Create encrypted snapshot of unencrypted volume\n"
                "2. Create new encrypted volume from snapshot\n"
                "3. Replace unencrypted volume with encrypted volume"
            ),
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["encryption", "ebs", "data-protection"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-kms-rotation",
            title="KMS Key Rotation Enabled",
            description=(
                "Ensure KMS keys have automatic rotation enabled. "
                "Key rotation limits the exposure if a key is compromised."
            ),
            severity="medium",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.KeyRotationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable automatic key rotation for KMS keys.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-12"]},
            tags=["encryption", "kms", "key-rotation"],
        ),
        # =====================================================================
        # CC6.2 - Authorization and Credentials
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.2-no-admin-policy",
            title="No Direct Admin Policy Attached",
            description=(
                "Ensure IAM users do not have AdministratorAccess policy directly attached. "
                "Users should use role-based access with proper approval workflows."
            ),
            severity="high",
            resource_types=["iam_user"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.AttachedPolicies",
                        operator=Operator.CONTAINS,
                        value="AdministratorAccess",
                    ),
                ],
            ),
            remediation="Remove AdministratorAccess policy from IAM users and use roles instead.",
            frameworks={"soc2": ["CC6.2"], "nist-800-53": ["AC-2", "AC-6"]},
            tags=["iam", "least-privilege", "authorization"],
        ),
        CheckDefinition(
            id="soc2-cc6.2-root-no-access-keys",
            title="Root Account No Access Keys",
            description=(
                "Ensure root account does not have access keys. "
                "Root account should be used only for initial setup and emergencies."
            ),
            severity="critical",
            resource_types=["iam_root_user"],
            condition=Condition(
                path="raw_data.AccessKeys",
                operator=Operator.IS_EMPTY,
            ),
            remediation="Delete access keys for root account. Use IAM users/roles for programmatic access.",
            frameworks={"soc2": ["CC6.2"], "nist-800-53": ["AC-2", "AC-6"]},
            tags=["iam", "root", "access-keys"],
        ),
        # =====================================================================
        # CC6.3 - Network Security
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.3-no-public-ssh",
            title="No Unrestricted SSH Access",
            description=(
                "Ensure security groups do not allow unrestricted SSH access (0.0.0.0/0:22). "
                "Unrestricted SSH access is a critical security vulnerability."
            ),
            severity="critical",
            resource_types=["ec2_security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.IngressRules",
                        operator=Operator.CONTAINS,
                        value="0.0.0.0/0:22",
                    ),
                ],
            ),
            remediation="Restrict SSH access to specific IP ranges or use VPN/bastion hosts.",
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["security-group", "network", "ssh"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-no-public-rdp",
            title="No Unrestricted RDP Access",
            description=(
                "Ensure security groups do not allow unrestricted RDP access (0.0.0.0/0:3389). "
                "Unrestricted RDP access is a critical security vulnerability."
            ),
            severity="critical",
            resource_types=["ec2_security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.IngressRules",
                        operator=Operator.CONTAINS,
                        value="0.0.0.0/0:3389",
                    ),
                ],
            ),
            remediation="Restrict RDP access to specific IP ranges or use VPN/bastion hosts.",
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["security-group", "network", "rdp"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-vpc-flow-logs",
            title="VPC Flow Logs Enabled",
            description=(
                "Ensure VPC flow logging is enabled. "
                "Flow logs capture IP traffic for security monitoring and incident investigation."
            ),
            severity="high",
            resource_types=["vpc"],
            condition=Condition(
                path="raw_data.FlowLogs",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation=(
                "Enable VPC flow logs:\n"
                "1. Navigate to VPC console\n"
                "2. Select the VPC\n"
                "3. Create flow log with appropriate destination (CloudWatch or S3)"
            ),
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AU-2", "AU-12"]},
            tags=["vpc", "flow-logs", "monitoring"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-default-sg-no-traffic",
            title="Default Security Group Restricts Traffic",
            description=(
                "Ensure default security group does not allow any traffic. "
                "Default security groups should be locked down to prevent unintended access."
            ),
            severity="medium",
            resource_types=["ec2_security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.OR,
                conditions=[
                    # Either not the default group
                    Condition(
                        path="raw_data.GroupName",
                        operator=Operator.NOT_EQUALS,
                        value="default",
                    ),
                    # Or has no rules (we check both ingress and egress)
                    ConditionGroup(
                        logic=LogicOperator.AND,
                        conditions=[
                            Condition(
                                path="raw_data.IpPermissions",
                                operator=Operator.IS_EMPTY,
                            ),
                            Condition(
                                path="raw_data.IpPermissionsEgress",
                                operator=Operator.IS_EMPTY,
                            ),
                        ],
                    ),
                ],
            ),
            remediation="Remove all inbound and outbound rules from default security group.",
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["SC-7"]},
            tags=["security-group", "network", "default"],
        ),
        # =====================================================================
        # CC6.6 - External Access Protection
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.6-s3-public-access-blocked",
            title="S3 Public Access Blocked",
            description=(
                "Ensure S3 buckets have public access blocked. "
                "Public S3 buckets are a common source of data breaches."
            ),
            severity="critical",
            resource_types=["s3_bucket"],
            condition=ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[
                    Condition(
                        path="raw_data.PublicAccessBlock.BlockPublicAcls",
                        operator=Operator.IS_TRUE,
                    ),
                    Condition(
                        path="raw_data.PublicAccessBlock.BlockPublicPolicy",
                        operator=Operator.IS_TRUE,
                    ),
                    Condition(
                        path="raw_data.PublicAccessBlock.IgnorePublicAcls",
                        operator=Operator.IS_TRUE,
                    ),
                    Condition(
                        path="raw_data.PublicAccessBlock.RestrictPublicBuckets",
                        operator=Operator.IS_TRUE,
                    ),
                ],
            ),
            remediation="Enable all public access block settings for S3 bucket.",
            frameworks={"soc2": ["CC6.6"], "nist-800-53": ["AC-3", "AC-21"]},
            tags=["s3", "public-access", "data-protection"],
        ),
        CheckDefinition(
            id="soc2-cc6.6-rds-not-public",
            title="RDS Not Publicly Accessible",
            description=(
                "Ensure RDS instances are not publicly accessible. "
                "Public databases are vulnerable to attacks from the internet."
            ),
            severity="critical",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.PubliclyAccessible",
                operator=Operator.IS_FALSE,
            ),
            remediation="Disable public accessibility for RDS instances.",
            frameworks={"soc2": ["CC6.6"], "nist-800-53": ["AC-3", "SC-7"]},
            tags=["rds", "public-access", "network"],
        ),
        CheckDefinition(
            id="soc2-cc6.6-ec2-imdsv2",
            title="EC2 Requires IMDSv2",
            description=(
                "Ensure EC2 instances require IMDSv2 for instance metadata service. "
                "IMDSv2 protects against SSRF attacks."
            ),
            severity="high",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.MetadataOptions.HttpTokens",
                operator=Operator.EQUALS,
                value="required",
            ),
            remediation="Modify instance metadata options to require IMDSv2.",
            frameworks={"soc2": ["CC6.6"], "nist-800-53": ["AC-3"]},
            tags=["ec2", "imds", "metadata"],
        ),
        # =====================================================================
        # CC6.7 - Access Key Rotation
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.7-access-key-rotation",
            title="IAM Access Keys Rotated",
            description=(
                "Ensure IAM access keys are rotated within 90 days. "
                "Regular key rotation reduces the risk of compromised credentials."
            ),
            severity="medium",
            resource_types=["iam_access_key"],
            condition=Condition(
                path="raw_data.CreateDate",
                operator=Operator.EXISTS,
            ),
            remediation="Rotate IAM access keys that are older than 90 days.",
            frameworks={"soc2": ["CC6.7"], "nist-800-53": ["AC-2"]},
            tags=["iam", "access-keys", "rotation"],
        ),
        # =====================================================================
        # CC7.2 - System Monitoring
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.2-cloudtrail-enabled",
            title="CloudTrail Enabled All Regions",
            description=(
                "Ensure CloudTrail is enabled in all regions. "
                "CloudTrail captures API activity for security monitoring and compliance."
            ),
            severity="critical",
            resource_types=["cloudtrail_trail"],
            condition=Condition(
                path="raw_data.IsMultiRegionTrail",
                operator=Operator.IS_TRUE,
            ),
            remediation=(
                "Enable CloudTrail in all regions:\n"
                "1. Navigate to CloudTrail console\n"
                "2. Create or update trail\n"
                "3. Enable 'Apply trail to all regions'"
            ),
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["AU-2", "AU-3"]},
            tags=["cloudtrail", "logging", "audit"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-cloudtrail-log-validation",
            title="CloudTrail Log Validation Enabled",
            description=(
                "Ensure CloudTrail log file validation is enabled. "
                "Log validation helps detect if logs were modified or deleted."
            ),
            severity="high",
            resource_types=["cloudtrail_trail"],
            condition=Condition(
                path="raw_data.LogFileValidationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable log file validation in CloudTrail settings.",
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["AU-9"]},
            tags=["cloudtrail", "logging", "integrity"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-cloudtrail-encryption",
            title="CloudTrail Logs Encrypted",
            description=(
                "Ensure CloudTrail logs are encrypted with KMS. "
                "Encryption protects audit logs from unauthorized access."
            ),
            severity="high",
            resource_types=["cloudtrail_trail"],
            condition=Condition(
                path="raw_data.KMSKeyId",
                operator=Operator.EXISTS,
            ),
            remediation="Configure CloudTrail to use KMS encryption for log files.",
            frameworks={"soc2": ["CC7.2", "CC6.1"], "nist-800-53": ["SC-28", "AU-9"]},
            tags=["cloudtrail", "encryption", "logging"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-config-enabled",
            title="AWS Config Enabled",
            description=(
                "Ensure AWS Config is enabled. "
                "Config provides configuration history and change notifications for compliance."
            ),
            severity="high",
            resource_types=["config_recorder"],
            condition=Condition(
                path="raw_data.RecordingGroup.AllSupported",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable AWS Config recording for all supported resources.",
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["CM-2", "CM-3"]},
            tags=["config", "monitoring", "compliance"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-guardduty-enabled",
            title="GuardDuty Enabled",
            description=(
                "Ensure GuardDuty is enabled. "
                "GuardDuty provides threat detection and continuous security monitoring."
            ),
            severity="high",
            resource_types=["guardduty_detector"],
            condition=Condition(
                path="raw_data.Status",
                operator=Operator.EQUALS,
                value="ENABLED",
            ),
            remediation="Enable GuardDuty in all regions.",
            frameworks={"soc2": ["CC7.2", "CC7.4"], "nist-800-53": ["SI-4", "IR-4"]},
            tags=["guardduty", "threat-detection", "monitoring"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-log-retention",
            title="CloudWatch Log Retention Set",
            description=(
                "Ensure CloudWatch log groups have retention policy. "
                "Log retention ensures logs are available for compliance audits."
            ),
            severity="medium",
            resource_types=["cloudwatch_log_group"],
            condition=Condition(
                path="raw_data.RetentionInDays",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=90,
            ),
            remediation="Set CloudWatch log group retention to at least 90 days.",
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["AU-11"]},
            tags=["cloudwatch", "logging", "retention"],
        ),
        # =====================================================================
        # CC7.3 - Backup and Recovery
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.3-rds-backup",
            title="RDS Automated Backups Enabled",
            description=(
                "Ensure RDS instances have automated backups enabled. "
                "Automated backups enable point-in-time recovery."
            ),
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.BackupRetentionPeriod",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=7,
            ),
            remediation="Enable automated backups with at least 7 days retention for RDS instances.",
            frameworks={"soc2": ["CC7.3", "A1.2"], "nist-800-53": ["CP-9"]},
            tags=["rds", "backup", "disaster-recovery"],
        ),
        CheckDefinition(
            id="soc2-cc7.3-rds-multi-az",
            title="RDS Multi-AZ Enabled",
            description=(
                "Ensure RDS instances have Multi-AZ deployment enabled. "
                "Multi-AZ provides high availability for disaster recovery."
            ),
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.MultiAZ",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Multi-AZ deployment for RDS instances.",
            frameworks={"soc2": ["CC7.3", "A1.2"], "nist-800-53": ["CP-10"]},
            tags=["rds", "availability", "disaster-recovery"],
        ),
        CheckDefinition(
            id="soc2-cc7.3-s3-versioning",
            title="S3 Bucket Versioning Enabled",
            description=(
                "Ensure S3 buckets have versioning enabled. "
                "Versioning provides data recovery capabilities."
            ),
            severity="medium",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Versioning.Status",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable versioning for S3 buckets containing critical data.",
            frameworks={"soc2": ["CC7.3", "A1.2"], "nist-800-53": ["CP-9"]},
            tags=["s3", "versioning", "backup"],
        ),
        # =====================================================================
        # CC8.1 - Change Management
        # =====================================================================
        CheckDefinition(
            id="soc2-cc8.1-config-tracking",
            title="AWS Config Change Tracking",
            description=(
                "Ensure AWS Config is tracking configuration changes. "
                "Config tracking provides audit trail for change management."
            ),
            severity="high",
            resource_types=["config_recorder"],
            condition=Condition(
                path="raw_data.Recording",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable AWS Config recording.",
            frameworks={"soc2": ["CC8.1"], "nist-800-53": ["CM-3"]},
            tags=["config", "change-management", "audit"],
        ),
        CheckDefinition(
            id="soc2-cc8.1-cloudtrail-cloudwatch",
            title="CloudTrail CloudWatch Integration",
            description=(
                "Ensure CloudTrail is integrated with CloudWatch Logs. "
                "Integration enables real-time monitoring of API calls."
            ),
            severity="medium",
            resource_types=["cloudtrail_trail"],
            condition=Condition(
                path="raw_data.CloudWatchLogsLogGroupArn",
                operator=Operator.EXISTS,
            ),
            remediation="Configure CloudTrail to send logs to CloudWatch Logs.",
            frameworks={"soc2": ["CC8.1", "CC7.2"], "nist-800-53": ["AU-6", "CM-3"]},
            tags=["cloudtrail", "cloudwatch", "monitoring"],
        ),
        # =====================================================================
        # CC9.2 - Risk Mitigation
        # =====================================================================
        CheckDefinition(
            id="soc2-cc9.2-securityhub-enabled",
            title="Security Hub Enabled",
            description=(
                "Ensure AWS Security Hub is enabled. "
                "Security Hub provides centralized security findings and compliance checks."
            ),
            severity="medium",
            resource_types=["securityhub_hub"],
            condition=Condition(
                path="raw_data.SubscribedAt",
                operator=Operator.EXISTS,
            ),
            remediation="Enable AWS Security Hub.",
            frameworks={"soc2": ["CC9.2", "CC7.2"], "nist-800-53": ["CA-7", "RA-5"]},
            tags=["securityhub", "compliance", "monitoring"],
        ),
        CheckDefinition(
            id="soc2-cc9.2-sns-encryption",
            title="SNS Topic Encryption",
            description=(
                "Ensure SNS topics are encrypted with KMS. "
                "Encryption protects sensitive data in transit."
            ),
            severity="medium",
            resource_types=["sns_topic"],
            condition=Condition(
                path="raw_data.KmsMasterKeyId",
                operator=Operator.EXISTS,
            ),
            remediation="Enable encryption for SNS topics using KMS.",
            frameworks={"soc2": ["CC9.2", "CC6.1"], "nist-800-53": ["SC-8"]},
            tags=["sns", "encryption", "messaging"],
        ),
        # =====================================================================
        # A1.2 - Availability
        # =====================================================================
        CheckDefinition(
            id="soc2-a1.2-asg-multi-az",
            title="Auto Scaling Group Multi-AZ",
            description=(
                "Ensure Auto Scaling Groups span multiple availability zones. "
                "Multi-AZ deployment provides high availability."
            ),
            severity="medium",
            resource_types=["autoscaling_group"],
            condition=Condition(
                path="raw_data.AvailabilityZones",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Configure Auto Scaling Group to use multiple availability zones.",
            frameworks={"soc2": ["A1.2"], "nist-800-53": ["CP-10"]},
            tags=["autoscaling", "availability", "disaster-recovery"],
        ),
        CheckDefinition(
            id="soc2-a1.2-elb-cross-zone",
            title="ELB Cross-Zone Load Balancing",
            description=(
                "Ensure ELB has cross-zone load balancing enabled. "
                "Cross-zone balancing distributes traffic across all instances."
            ),
            severity="low",
            resource_types=["elb_load_balancer"],
            condition=Condition(
                path="raw_data.CrossZoneLoadBalancing.Enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable cross-zone load balancing for ELB.",
            frameworks={"soc2": ["A1.2"], "nist-800-53": ["CP-10"]},
            tags=["elb", "availability", "load-balancing"],
        ),
    ]


def create_soc2_evaluator() -> Evaluator:
    """
    Create an evaluator pre-loaded with SOC 2 checks.

    Returns:
        Evaluator with all SOC 2 checks registered.
    """
    evaluator = Evaluator()

    for check in get_soc2_aws_checks():
        evaluator.register_check(check)

    logger.info(f"Created SOC 2 evaluator with {len(evaluator._checks)} checks")
    return evaluator


def get_soc2_framework() -> SOC2Framework:
    """
    Get the complete SOC 2 framework definition.

    Returns:
        SOC2Framework with all controls and check mappings.
    """
    framework = SOC2Framework(
        version=SOC2_VERSION,
        controls=SOC2_CONTROLS,
    )

    # Build check mappings
    for check in get_soc2_aws_checks():
        soc2_controls = check.frameworks.get("soc2", [])
        for control_id in soc2_controls:
            if control_id not in framework.check_mappings:
                framework.check_mappings[control_id] = []
            framework.check_mappings[control_id].append(check.id)

    return framework
