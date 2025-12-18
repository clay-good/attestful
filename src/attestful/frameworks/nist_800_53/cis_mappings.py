"""
CIS Benchmark to NIST 800-53 Control Mappings.

Provides crosswalk mappings from CIS Benchmark checks to NIST 800-53 Rev 5 controls.
These mappings enable inheriting compliance evidence from CIS checks for NIST 800-53
assessments.

Mapping sources:
- NIST SP 800-53 Rev 5 to CIS Controls v8 mapping
- CIS AWS Foundations Benchmark to NIST 800-53 crosswalk
- Professional judgment based on control requirements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from attestful.core.logging import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


@dataclass
class CISMapping:
    """Mapping from a CIS check to NIST 800-53 controls."""

    cis_check_id: str
    cis_check_name: str
    nist_controls: list[str]
    mapping_rationale: str = ""
    confidence: str = "high"  # high, medium, low


# =============================================================================
# CIS AWS Foundations Benchmark Mappings
# =============================================================================

CIS_AWS_TO_NIST_800_53: dict[str, CISMapping] = {
    # Section 1: Identity and Access Management
    "cis-1.1": CISMapping(
        cis_check_id="cis-1.1",
        cis_check_name="Avoid the use of root account",
        nist_controls=["AC-2", "AC-6", "AC-6(1)", "AC-6(2)"],
        mapping_rationale="Root account avoidance aligns with least privilege and account management",
    ),
    "cis-1.2": CISMapping(
        cis_check_id="cis-1.2",
        cis_check_name="Ensure MFA is enabled for all IAM users with console password",
        nist_controls=["IA-2", "IA-2(1)", "IA-2(2)"],
        mapping_rationale="MFA requirement for identification and authentication",
    ),
    "cis-1.3": CISMapping(
        cis_check_id="cis-1.3",
        cis_check_name="Ensure credentials unused for 90 days or greater are disabled",
        nist_controls=["AC-2", "AC-2(3)", "IA-5"],
        mapping_rationale="Credential lifecycle management",
    ),
    "cis-1.4": CISMapping(
        cis_check_id="cis-1.4",
        cis_check_name="Ensure access keys are rotated every 90 days or less",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Authenticator management and rotation",
    ),
    "cis-1.5": CISMapping(
        cis_check_id="cis-1.5",
        cis_check_name="Ensure IAM password policy requires at least one uppercase letter",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password complexity requirements",
    ),
    "cis-1.6": CISMapping(
        cis_check_id="cis-1.6",
        cis_check_name="Ensure IAM password policy requires at least one lowercase letter",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password complexity requirements",
    ),
    "cis-1.7": CISMapping(
        cis_check_id="cis-1.7",
        cis_check_name="Ensure IAM password policy requires at least one symbol",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password complexity requirements",
    ),
    "cis-1.8": CISMapping(
        cis_check_id="cis-1.8",
        cis_check_name="Ensure IAM password policy requires at least one number",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password complexity requirements",
    ),
    "cis-1.9": CISMapping(
        cis_check_id="cis-1.9",
        cis_check_name="Ensure IAM password policy requires minimum length of 14 or greater",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password length requirements",
    ),
    "cis-1.10": CISMapping(
        cis_check_id="cis-1.10",
        cis_check_name="Ensure IAM password policy prevents password reuse",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password reuse prevention",
    ),
    "cis-1.11": CISMapping(
        cis_check_id="cis-1.11",
        cis_check_name="Ensure IAM password policy expires passwords within 90 days or less",
        nist_controls=["IA-5", "IA-5(1)"],
        mapping_rationale="Password expiration requirements",
    ),
    "cis-1.12": CISMapping(
        cis_check_id="cis-1.12",
        cis_check_name="Ensure no root account access key exists",
        nist_controls=["AC-2", "AC-6", "IA-2"],
        mapping_rationale="Root account protection",
    ),
    "cis-1.13": CISMapping(
        cis_check_id="cis-1.13",
        cis_check_name="Ensure MFA is enabled for the root account",
        nist_controls=["IA-2", "IA-2(1)", "IA-2(11)"],
        mapping_rationale="Root account MFA requirement",
    ),
    "cis-1.14": CISMapping(
        cis_check_id="cis-1.14",
        cis_check_name="Ensure hardware MFA is enabled for the root account",
        nist_controls=["IA-2", "IA-2(1)", "IA-2(11)"],
        mapping_rationale="Hardware MFA for privileged accounts",
    ),
    "cis-1.15": CISMapping(
        cis_check_id="cis-1.15",
        cis_check_name="Ensure security questions are registered in the AWS account",
        nist_controls=["AC-2", "IA-5"],
        mapping_rationale="Account recovery mechanisms",
    ),
    "cis-1.16": CISMapping(
        cis_check_id="cis-1.16",
        cis_check_name="Ensure IAM policies are attached only to groups or roles",
        nist_controls=["AC-2", "AC-6"],
        mapping_rationale="Policy attachment best practices",
    ),
    "cis-1.17": CISMapping(
        cis_check_id="cis-1.17",
        cis_check_name="Maintain current contact details",
        nist_controls=["IR-6", "IR-7"],
        mapping_rationale="Incident response contact information",
    ),
    "cis-1.18": CISMapping(
        cis_check_id="cis-1.18",
        cis_check_name="Ensure security contact information is registered",
        nist_controls=["IR-6", "IR-7"],
        mapping_rationale="Security contact for incident response",
    ),
    "cis-1.19": CISMapping(
        cis_check_id="cis-1.19",
        cis_check_name="Ensure IAM instance roles are used for AWS resource access",
        nist_controls=["AC-2", "AC-3", "IA-2"],
        mapping_rationale="Instance role usage for access control",
    ),
    "cis-1.20": CISMapping(
        cis_check_id="cis-1.20",
        cis_check_name="Ensure a support role has been created for managing incidents",
        nist_controls=["IR-4", "IR-7"],
        mapping_rationale="Incident management roles",
    ),
    "cis-1.21": CISMapping(
        cis_check_id="cis-1.21",
        cis_check_name="Do not setup access keys during initial user setup",
        nist_controls=["AC-2", "IA-5"],
        mapping_rationale="Secure account provisioning",
    ),
    "cis-1.22": CISMapping(
        cis_check_id="cis-1.22",
        cis_check_name="Ensure IAM users receive permissions only through groups",
        nist_controls=["AC-2", "AC-6"],
        mapping_rationale="Group-based access management",
    ),

    # Section 2: Storage
    "cis-2.1.1": CISMapping(
        cis_check_id="cis-2.1.1",
        cis_check_name="Ensure S3 bucket has encryption enabled",
        nist_controls=["SC-13", "SC-28", "SC-28(1)"],
        mapping_rationale="Data-at-rest encryption",
    ),
    "cis-2.1.2": CISMapping(
        cis_check_id="cis-2.1.2",
        cis_check_name="Ensure S3 bucket has versioning enabled",
        nist_controls=["CP-9", "CP-10", "SI-12"],
        mapping_rationale="Data backup and recovery",
    ),
    "cis-2.1.3": CISMapping(
        cis_check_id="cis-2.1.3",
        cis_check_name="Ensure S3 bucket has access logging enabled",
        nist_controls=["AU-2", "AU-3", "AU-12"],
        mapping_rationale="Access logging for audit",
    ),
    "cis-2.1.4": CISMapping(
        cis_check_id="cis-2.1.4",
        cis_check_name="Ensure S3 bucket has MFA Delete enabled",
        nist_controls=["AC-3", "AC-6", "IA-2(1)"],
        mapping_rationale="MFA for destructive operations",
    ),
    "cis-2.2.1": CISMapping(
        cis_check_id="cis-2.2.1",
        cis_check_name="Ensure EBS volume encryption is enabled",
        nist_controls=["SC-13", "SC-28"],
        mapping_rationale="EBS volume encryption at rest",
    ),
    "cis-2.3.1": CISMapping(
        cis_check_id="cis-2.3.1",
        cis_check_name="Ensure RDS instances have encryption enabled",
        nist_controls=["SC-13", "SC-28"],
        mapping_rationale="RDS encryption at rest",
    ),

    # Section 3: Logging
    "cis-3.1": CISMapping(
        cis_check_id="cis-3.1",
        cis_check_name="Ensure CloudTrail is enabled in all regions",
        nist_controls=["AU-2", "AU-3", "AU-12"],
        mapping_rationale="Multi-region audit logging",
    ),
    "cis-3.2": CISMapping(
        cis_check_id="cis-3.2",
        cis_check_name="Ensure CloudTrail log file validation is enabled",
        nist_controls=["AU-9", "AU-9(3)", "SI-7"],
        mapping_rationale="Log integrity validation",
    ),
    "cis-3.3": CISMapping(
        cis_check_id="cis-3.3",
        cis_check_name="Ensure CloudTrail S3 bucket is not publicly accessible",
        nist_controls=["AC-3", "AU-9", "SC-7"],
        mapping_rationale="Audit log access control",
    ),
    "cis-3.4": CISMapping(
        cis_check_id="cis-3.4",
        cis_check_name="Ensure CloudTrail logs are integrated with CloudWatch Logs",
        nist_controls=["AU-6", "SI-4", "SI-4(2)"],
        mapping_rationale="Centralized log monitoring",
    ),
    "cis-3.5": CISMapping(
        cis_check_id="cis-3.5",
        cis_check_name="Ensure AWS Config is enabled in all regions",
        nist_controls=["CM-8", "CA-7", "SI-4"],
        mapping_rationale="Configuration monitoring",
    ),
    "cis-3.6": CISMapping(
        cis_check_id="cis-3.6",
        cis_check_name="Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket",
        nist_controls=["AU-2", "AU-3", "AU-9"],
        mapping_rationale="Audit trail logging",
    ),
    "cis-3.7": CISMapping(
        cis_check_id="cis-3.7",
        cis_check_name="Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
        nist_controls=["AU-9", "SC-13", "SC-28"],
        mapping_rationale="Audit log encryption",
    ),
    "cis-3.8": CISMapping(
        cis_check_id="cis-3.8",
        cis_check_name="Ensure rotation for customer-created KMS keys is enabled",
        nist_controls=["SC-12", "SC-12(1)"],
        mapping_rationale="Cryptographic key rotation",
    ),
    "cis-3.9": CISMapping(
        cis_check_id="cis-3.9",
        cis_check_name="Ensure VPC flow logging is enabled in all VPCs",
        nist_controls=["AU-2", "AU-12", "AC-4", "SI-4"],
        mapping_rationale="Network flow logging",
    ),
    "cis-3.10": CISMapping(
        cis_check_id="cis-3.10",
        cis_check_name="Ensure object-level logging for write events is enabled for S3 bucket",
        nist_controls=["AU-2", "AU-3", "AU-12"],
        mapping_rationale="S3 data event logging",
    ),
    "cis-3.11": CISMapping(
        cis_check_id="cis-3.11",
        cis_check_name="Ensure object-level logging for read events is enabled for S3 bucket",
        nist_controls=["AU-2", "AU-3", "AU-12"],
        mapping_rationale="S3 data event logging",
    ),

    # Section 4: Monitoring
    "cis-4.1": CISMapping(
        cis_check_id="cis-4.1",
        cis_check_name="Ensure unauthorized API calls are monitored",
        nist_controls=["SI-4", "AU-6", "IR-4"],
        mapping_rationale="Security event monitoring",
    ),
    "cis-4.2": CISMapping(
        cis_check_id="cis-4.2",
        cis_check_name="Ensure console sign-in without MFA is monitored",
        nist_controls=["SI-4", "IA-2(1)", "AU-6"],
        mapping_rationale="Authentication monitoring",
    ),
    "cis-4.3": CISMapping(
        cis_check_id="cis-4.3",
        cis_check_name="Ensure root account usage is monitored",
        nist_controls=["SI-4", "AC-6", "AU-6"],
        mapping_rationale="Privileged account monitoring",
    ),
    "cis-4.4": CISMapping(
        cis_check_id="cis-4.4",
        cis_check_name="Ensure IAM policy changes are monitored",
        nist_controls=["SI-4", "AC-2", "AU-6"],
        mapping_rationale="Policy change monitoring",
    ),
    "cis-4.5": CISMapping(
        cis_check_id="cis-4.5",
        cis_check_name="Ensure CloudTrail configuration changes are monitored",
        nist_controls=["SI-4", "AU-9", "AU-6"],
        mapping_rationale="Audit configuration monitoring",
    ),
    "cis-4.6": CISMapping(
        cis_check_id="cis-4.6",
        cis_check_name="Ensure console authentication failures are monitored",
        nist_controls=["SI-4", "AU-6", "AC-7"],
        mapping_rationale="Failed authentication monitoring",
    ),
    "cis-4.7": CISMapping(
        cis_check_id="cis-4.7",
        cis_check_name="Ensure KMS key disabling or deletion is monitored",
        nist_controls=["SI-4", "SC-12", "AU-6"],
        mapping_rationale="Key management monitoring",
    ),
    "cis-4.8": CISMapping(
        cis_check_id="cis-4.8",
        cis_check_name="Ensure S3 bucket policy changes are monitored",
        nist_controls=["SI-4", "AC-3", "AU-6"],
        mapping_rationale="Access policy monitoring",
    ),
    "cis-4.9": CISMapping(
        cis_check_id="cis-4.9",
        cis_check_name="Ensure AWS Config configuration changes are monitored",
        nist_controls=["SI-4", "CM-3", "AU-6"],
        mapping_rationale="Configuration monitoring",
    ),
    "cis-4.10": CISMapping(
        cis_check_id="cis-4.10",
        cis_check_name="Ensure security group changes are monitored",
        nist_controls=["SI-4", "SC-7", "AU-6"],
        mapping_rationale="Network security monitoring",
    ),
    "cis-4.11": CISMapping(
        cis_check_id="cis-4.11",
        cis_check_name="Ensure Network ACL changes are monitored",
        nist_controls=["SI-4", "SC-7", "AU-6"],
        mapping_rationale="Network ACL monitoring",
    ),
    "cis-4.12": CISMapping(
        cis_check_id="cis-4.12",
        cis_check_name="Ensure changes to network gateways are monitored",
        nist_controls=["SI-4", "SC-7", "AU-6"],
        mapping_rationale="Network gateway monitoring",
    ),
    "cis-4.13": CISMapping(
        cis_check_id="cis-4.13",
        cis_check_name="Ensure route table changes are monitored",
        nist_controls=["SI-4", "SC-7", "AU-6"],
        mapping_rationale="Network routing monitoring",
    ),
    "cis-4.14": CISMapping(
        cis_check_id="cis-4.14",
        cis_check_name="Ensure VPC changes are monitored",
        nist_controls=["SI-4", "SC-7", "AU-6"],
        mapping_rationale="VPC configuration monitoring",
    ),
    "cis-4.15": CISMapping(
        cis_check_id="cis-4.15",
        cis_check_name="Ensure AWS Organizations changes are monitored",
        nist_controls=["SI-4", "AC-2", "AU-6"],
        mapping_rationale="Organization changes monitoring",
    ),

    # Section 5: Networking
    "cis-5.1": CISMapping(
        cis_check_id="cis-5.1",
        cis_check_name="Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports",
        nist_controls=["SC-7", "SC-7(5)", "AC-17"],
        mapping_rationale="Network access control",
    ),
    "cis-5.2": CISMapping(
        cis_check_id="cis-5.2",
        cis_check_name="Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports",
        nist_controls=["SC-7", "SC-7(5)", "AC-17"],
        mapping_rationale="Security group restrictions",
    ),
    "cis-5.3": CISMapping(
        cis_check_id="cis-5.3",
        cis_check_name="Ensure VPC default security group restricts all traffic",
        nist_controls=["SC-7", "CM-7", "AC-4"],
        mapping_rationale="Default deny networking",
    ),
    "cis-5.4": CISMapping(
        cis_check_id="cis-5.4",
        cis_check_name="Ensure routing tables for VPC peering are least access",
        nist_controls=["AC-4", "SC-7"],
        mapping_rationale="Network segmentation",
    ),
}


# =============================================================================
# CIS Azure Foundations Benchmark Mappings
# =============================================================================

CIS_AZURE_TO_NIST_800_53: dict[str, CISMapping] = {
    "cis-1.1": CISMapping(
        cis_check_id="cis-1.1",
        cis_check_name="Ensure multi-factor authentication is enabled for all privileged users",
        nist_controls=["IA-2", "IA-2(1)", "IA-2(2)"],
        mapping_rationale="MFA for privileged accounts",
    ),
    "cis-1.2": CISMapping(
        cis_check_id="cis-1.2",
        cis_check_name="Ensure multi-factor authentication is enabled for all non-privileged users",
        nist_controls=["IA-2", "IA-2(1)"],
        mapping_rationale="MFA for all users",
    ),
    "cis-2.1": CISMapping(
        cis_check_id="cis-2.1",
        cis_check_name="Ensure Azure Defender is enabled for all resources",
        nist_controls=["SI-4", "SI-4(2)", "RA-5"],
        mapping_rationale="Security monitoring and vulnerability detection",
    ),
    "cis-3.1": CISMapping(
        cis_check_id="cis-3.1",
        cis_check_name="Ensure storage account secure transfer required is enabled",
        nist_controls=["SC-8", "SC-8(1)", "SC-13"],
        mapping_rationale="Encryption in transit",
    ),
    "cis-3.2": CISMapping(
        cis_check_id="cis-3.2",
        cis_check_name="Ensure storage account blob service encryption is enabled",
        nist_controls=["SC-13", "SC-28"],
        mapping_rationale="Encryption at rest",
    ),
    "cis-4.1": CISMapping(
        cis_check_id="cis-4.1",
        cis_check_name="Ensure SQL server TDE is enabled",
        nist_controls=["SC-13", "SC-28"],
        mapping_rationale="Database encryption at rest",
    ),
    "cis-5.1": CISMapping(
        cis_check_id="cis-5.1",
        cis_check_name="Ensure Activity Log Alert exists for Create Policy Assignment",
        nist_controls=["SI-4", "AU-6", "AU-12"],
        mapping_rationale="Policy change alerting",
    ),
    "cis-6.1": CISMapping(
        cis_check_id="cis-6.1",
        cis_check_name="Ensure NSG flow logs are enabled",
        nist_controls=["AU-2", "AU-12", "SI-4"],
        mapping_rationale="Network flow logging",
    ),
    "cis-6.2": CISMapping(
        cis_check_id="cis-6.2",
        cis_check_name="Ensure NSG rules do not allow SSH from internet",
        nist_controls=["SC-7", "SC-7(5)", "AC-17"],
        mapping_rationale="Network boundary protection",
    ),
    "cis-6.3": CISMapping(
        cis_check_id="cis-6.3",
        cis_check_name="Ensure NSG rules do not allow RDP from internet",
        nist_controls=["SC-7", "SC-7(5)", "AC-17"],
        mapping_rationale="Network boundary protection",
    ),
}


# =============================================================================
# CIS GCP Foundations Benchmark Mappings
# =============================================================================

CIS_GCP_TO_NIST_800_53: dict[str, CISMapping] = {
    "cis-1.1": CISMapping(
        cis_check_id="cis-1.1",
        cis_check_name="Ensure corporate login credentials are used",
        nist_controls=["AC-2", "IA-2"],
        mapping_rationale="Corporate identity usage",
    ),
    "cis-1.2": CISMapping(
        cis_check_id="cis-1.2",
        cis_check_name="Ensure 2-step verification is enabled for all users",
        nist_controls=["IA-2", "IA-2(1)"],
        mapping_rationale="Multi-factor authentication",
    ),
    "cis-2.1": CISMapping(
        cis_check_id="cis-2.1",
        cis_check_name="Ensure Cloud Audit Logging is enabled for all services",
        nist_controls=["AU-2", "AU-3", "AU-12"],
        mapping_rationale="Comprehensive audit logging",
    ),
    "cis-3.1": CISMapping(
        cis_check_id="cis-3.1",
        cis_check_name="Ensure VPC flow logging is enabled",
        nist_controls=["AU-2", "AU-12", "SI-4"],
        mapping_rationale="Network flow logging",
    ),
    "cis-4.1": CISMapping(
        cis_check_id="cis-4.1",
        cis_check_name="Ensure GCE VM instances do not have public IP addresses",
        nist_controls=["AC-17", "SC-7"],
        mapping_rationale="Network exposure reduction",
    ),
    "cis-5.1": CISMapping(
        cis_check_id="cis-5.1",
        cis_check_name="Ensure Cloud Storage bucket is not anonymously accessible",
        nist_controls=["AC-3", "SC-7"],
        mapping_rationale="Storage access control",
    ),
    "cis-5.2": CISMapping(
        cis_check_id="cis-5.2",
        cis_check_name="Ensure Cloud Storage bucket has uniform bucket-level access enabled",
        nist_controls=["AC-3", "AC-6"],
        mapping_rationale="Consistent access control",
    ),
    "cis-6.1": CISMapping(
        cis_check_id="cis-6.1",
        cis_check_name="Ensure Cloud SQL database instances require SSL",
        nist_controls=["SC-8", "SC-8(1)", "SC-13"],
        mapping_rationale="Encryption in transit",
    ),
}


# =============================================================================
# Utility Functions
# =============================================================================


def get_cis_to_nist_mapping(cis_check_id: str, provider: str = "aws") -> CISMapping | None:
    """
    Get NIST 800-53 controls mapped to a CIS check.

    Args:
        cis_check_id: CIS check ID (e.g., "cis-1.1")
        provider: Cloud provider ("aws", "azure", "gcp")

    Returns:
        CISMapping if found, None otherwise
    """
    mapping_tables = {
        "aws": CIS_AWS_TO_NIST_800_53,
        "azure": CIS_AZURE_TO_NIST_800_53,
        "gcp": CIS_GCP_TO_NIST_800_53,
    }

    mapping_table = mapping_tables.get(provider.lower(), {})
    return mapping_table.get(cis_check_id)


def get_nist_controls_for_cis(cis_check_id: str, provider: str = "aws") -> list[str]:
    """
    Get NIST 800-53 control IDs mapped to a CIS check.

    Args:
        cis_check_id: CIS check ID (e.g., "cis-1.1")
        provider: Cloud provider ("aws", "azure", "gcp")

    Returns:
        List of NIST 800-53 control IDs
    """
    mapping = get_cis_to_nist_mapping(cis_check_id, provider)
    return mapping.nist_controls if mapping else []


def get_cis_checks_for_nist(nist_control_id: str, provider: str | None = None) -> list[CISMapping]:
    """
    Get all CIS checks mapped to a NIST 800-53 control.

    Args:
        nist_control_id: NIST 800-53 control ID (e.g., "AC-2")
        provider: Optional provider filter ("aws", "azure", "gcp")

    Returns:
        List of CISMapping objects
    """
    results: list[CISMapping] = []
    nist_id_upper = nist_control_id.upper()

    mapping_tables = {
        "aws": CIS_AWS_TO_NIST_800_53,
        "azure": CIS_AZURE_TO_NIST_800_53,
        "gcp": CIS_GCP_TO_NIST_800_53,
    }

    tables_to_search = (
        {provider.lower(): mapping_tables[provider.lower()]}
        if provider
        else mapping_tables
    )

    for table in tables_to_search.values():
        for mapping in table.values():
            if nist_id_upper in [c.upper() for c in mapping.nist_controls]:
                results.append(mapping)

    return results


def get_all_mapped_nist_controls(provider: str | None = None) -> set[str]:
    """
    Get all NIST 800-53 controls that have CIS mappings.

    Args:
        provider: Optional provider filter

    Returns:
        Set of NIST 800-53 control IDs
    """
    controls: set[str] = set()

    mapping_tables = {
        "aws": CIS_AWS_TO_NIST_800_53,
        "azure": CIS_AZURE_TO_NIST_800_53,
        "gcp": CIS_GCP_TO_NIST_800_53,
    }

    tables_to_search = (
        {provider.lower(): mapping_tables[provider.lower()]}
        if provider
        else mapping_tables
    )

    for table in tables_to_search.values():
        for mapping in table.values():
            controls.update(mapping.nist_controls)

    return controls


def get_mapping_statistics() -> dict:
    """
    Get statistics about CIS to NIST 800-53 mappings.

    Returns:
        Dictionary with mapping statistics
    """
    aws_controls = get_all_mapped_nist_controls("aws")
    azure_controls = get_all_mapped_nist_controls("azure")
    gcp_controls = get_all_mapped_nist_controls("gcp")
    all_controls = aws_controls | azure_controls | gcp_controls

    return {
        "total_cis_checks_mapped": (
            len(CIS_AWS_TO_NIST_800_53) +
            len(CIS_AZURE_TO_NIST_800_53) +
            len(CIS_GCP_TO_NIST_800_53)
        ),
        "aws_checks_mapped": len(CIS_AWS_TO_NIST_800_53),
        "azure_checks_mapped": len(CIS_AZURE_TO_NIST_800_53),
        "gcp_checks_mapped": len(CIS_GCP_TO_NIST_800_53),
        "unique_nist_controls_covered": len(all_controls),
        "aws_nist_controls": len(aws_controls),
        "azure_nist_controls": len(azure_controls),
        "gcp_nist_controls": len(gcp_controls),
    }


__all__ = [
    # Data classes
    "CISMapping",
    # Mapping tables
    "CIS_AWS_TO_NIST_800_53",
    "CIS_AZURE_TO_NIST_800_53",
    "CIS_GCP_TO_NIST_800_53",
    # Functions
    "get_cis_to_nist_mapping",
    "get_nist_controls_for_cis",
    "get_cis_checks_for_nist",
    "get_all_mapped_nist_controls",
    "get_mapping_statistics",
]
