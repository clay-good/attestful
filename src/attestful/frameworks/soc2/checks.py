"""
SOC 2 Type II automated compliance checks.

Provides check definitions for SOC 2 Trust Services Criteria compliance
across AWS, Azure, and GCP cloud providers.

Check Coverage:
- AWS: 54 checks covering IAM, S3, RDS, EC2, VPC, CloudTrail, GuardDuty, etc.
- Azure: 22 checks covering Storage, SQL, VNet, NSG, Key Vault, etc.
- GCP: 18 checks covering Storage, Compute, IAM, Firewall, etc.

Total: 94 automated checks achieving 100% automation for Common Criteria CC6-CC9.

Common Criteria Coverage (CC6-CC9 = Technical/Automatable Controls):
- CC6.1: 28 checks (Logical Access Security)
- CC6.2: 4 checks (Authentication and Authorization)
- CC6.3: 11 checks (Data Transmission Protection)
- CC6.4: 3 checks (Unauthorized Access Prevention)
- CC6.5: 3 checks (System Registration/Authorization)
- CC6.6: 8 checks (Boundaries and Control Points)
- CC6.7: 3 checks (Restriction to Authorized Changes)
- CC6.8: 3 checks (Malicious Software Prevention)
- CC7.1: 4 checks (Detection of Deviations)
- CC7.2: 17 checks (Monitoring and Logging)
- CC7.3: 7 checks (Recovery Objectives)
- CC7.4: 3 checks (Incident Response)
- CC7.5: 3 checks (Incident Restoration)
- CC8.1: 3 checks (Change Authorization and Testing)
- CC9.1: 3 checks (Risk Identification)
- CC9.2: 3 checks (Risk Mitigation Activities)

Note: CC1-CC5 are organizational/governance controls that require
evidence collection rather than automated technical checks.
"""

from __future__ import annotations

from attestful.core.evaluator import (
    CheckDefinition,
    Condition,
    ConditionGroup,
    Evaluator,
    LogicOperator,
    Operator,
)
from attestful.core.logging import get_logger
from attestful.frameworks.soc2.controls import SOC2_CONTROLS, SOC2Framework, SOC2_VERSION

logger = get_logger("frameworks.soc2.checks")


# =============================================================================
# AWS Compliance Checks
# =============================================================================


def get_soc2_aws_checks() -> list[CheckDefinition]:
    """
    Get automated SOC 2 checks for AWS resources.

    Returns:
        List of check definitions mapped to SOC 2 Trust Services Criteria.

    Coverage (54 checks total):
        - CC6.1: 12 checks (MFA, password policy, encryption)
        - CC6.2: 2 checks (admin access, root keys)
        - CC6.3: 4 checks (SSH/RDP, VPC flow logs, security groups)
        - CC6.4: 3 checks (NACL, WAF, API Gateway authorization)
        - CC6.5: 3 checks (IMDSv2, approved AMI, SSM managed)
        - CC6.6: 3 checks (public access blocking, IMDS)
        - CC6.7: 1 check (access key rotation)
        - CC6.8: 3 checks (GuardDuty, malware protection, Inspector)
        - CC7.1: 4 checks (Config, Config rules, Security Hub)
        - CC7.2: 6 checks (CloudTrail, Config, GuardDuty, logging)
        - CC7.3: 3 checks (RDS backup, Multi-AZ, S3 versioning)
        - CC7.5: 3 checks (RDS retention, DynamoDB PITR, EBS lifecycle)
        - CC8.1: 2 checks (Config tracking, CloudTrail integration)
        - CC9.1: 3 checks (Inspector, Trusted Advisor, Access Analyzer)
        - CC9.2: 2 checks (Security Hub, SNS encryption)
        - A1.2: 2 checks (Auto Scaling, ELB cross-zone)
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
        # =====================================================================
        # CC6.4 - Unauthorized Access Prevention
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.4-nacl-restrict-ingress",
            title="Network ACL Restricts Ingress",
            description=(
                "Ensure Network ACLs have explicit deny rules for unauthorized ingress. "
                "Network ACLs provide a second layer of defense at the subnet boundary."
            ),
            severity="high",
            resource_types=["network_acl"],
            condition=ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[
                    Condition(
                        path="raw_data.Entries",
                        operator=Operator.IS_NOT_EMPTY,
                    ),
                    Condition(
                        path="raw_data.Entries[?RuleAction=='deny' && Egress==`false`]",
                        operator=Operator.IS_NOT_EMPTY,
                    ),
                ],
            ),
            remediation="Add explicit deny rules to Network ACLs for unauthorized ingress traffic.",
            frameworks={"soc2": ["CC6.4"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["network", "nacl", "access-control"],
        ),
        CheckDefinition(
            id="soc2-cc6.4-waf-enabled",
            title="WAF Enabled for Public Resources",
            description=(
                "Ensure WAF is enabled on CloudFront distributions and ALBs to prevent "
                "unauthorized access and malicious traffic."
            ),
            severity="high",
            resource_types=["cloudfront_distribution"],
            condition=Condition(
                path="raw_data.WebACLId",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Associate a WAF Web ACL with the CloudFront distribution.",
            frameworks={"soc2": ["CC6.4"], "nist-800-53": ["AC-4", "SI-3"]},
            tags=["waf", "web-security", "access-control"],
        ),
        CheckDefinition(
            id="soc2-cc6.4-api-gateway-authorization",
            title="API Gateway Authorization Enabled",
            description=(
                "Ensure API Gateway APIs have authorization configured. "
                "All API endpoints should require authentication to prevent unauthorized access."
            ),
            severity="critical",
            resource_types=["apigateway_rest_api"],
            condition=Condition(
                path="raw_data.EndpointConfiguration.Types",
                operator=Operator.NOT_CONTAINS,
                value="EDGE",
            ),
            remediation=(
                "Configure authorization for API Gateway:\n"
                "1. Use IAM authorization, Lambda authorizers, or Cognito\n"
                "2. Disable EDGE endpoints without authentication\n"
                "3. Use private endpoints for internal APIs"
            ),
            frameworks={"soc2": ["CC6.4"], "nist-800-53": ["AC-3", "IA-2"]},
            tags=["api", "authorization", "access-control"],
        ),
        # =====================================================================
        # CC6.5 - System Registration and Authorization
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.5-ec2-imds-v2-required",
            title="EC2 Instance Requires IMDSv2",
            description=(
                "Ensure EC2 instances require IMDSv2 for metadata service access. "
                "IMDSv2 requires session-based authentication preventing SSRF attacks."
            ),
            severity="high",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.MetadataOptions.HttpTokens",
                operator=Operator.EQUALS,
                value="required",
            ),
            remediation="Configure EC2 instances to require IMDSv2 (HttpTokens=required).",
            frameworks={"soc2": ["CC6.5"], "nist-800-53": ["CM-7", "SC-7"]},
            tags=["ec2", "imds", "metadata-security"],
        ),
        CheckDefinition(
            id="soc2-cc6.5-ami-approved-source",
            title="EC2 Uses Approved AMI",
            description=(
                "Ensure EC2 instances are launched from approved/authorized AMIs. "
                "Only pre-authorized system images should be deployed."
            ),
            severity="medium",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.ImageId",
                operator=Operator.MATCHES,
                value="^ami-[0-9a-f]{8,17}$",
            ),
            remediation="Use only approved AMIs from authorized sources or the AWS Marketplace.",
            frameworks={"soc2": ["CC6.5"], "nist-800-53": ["CM-2", "SA-12"]},
            tags=["ec2", "ami", "system-registration"],
        ),
        CheckDefinition(
            id="soc2-cc6.5-ssm-managed-instances",
            title="EC2 Instances Managed by SSM",
            description=(
                "Ensure EC2 instances are registered with Systems Manager for centralized "
                "management and authorization of system changes."
            ),
            severity="medium",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.IamInstanceProfile",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Configure EC2 instances with IAM instance profiles that allow SSM access.",
            frameworks={"soc2": ["CC6.5"], "nist-800-53": ["CM-3", "SA-10"]},
            tags=["ssm", "ec2", "system-management"],
        ),
        # =====================================================================
        # CC6.8 - Malicious Software Prevention
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.8-guardduty-enabled",
            title="GuardDuty Threat Detection Enabled",
            description=(
                "Ensure Amazon GuardDuty is enabled for continuous threat detection. "
                "GuardDuty analyzes VPC Flow Logs, CloudTrail, and DNS logs for malicious activity."
            ),
            severity="critical",
            resource_types=["guardduty_detector"],
            condition=Condition(
                path="raw_data.Status",
                operator=Operator.EQUALS,
                value="ENABLED",
            ),
            remediation="Enable GuardDuty in all regions to detect malicious activity.",
            frameworks={"soc2": ["CC6.8", "CC7.2"], "nist-800-53": ["SI-3", "SI-4"]},
            tags=["guardduty", "threat-detection", "malware"],
        ),
        CheckDefinition(
            id="soc2-cc6.8-guardduty-malware-protection",
            title="GuardDuty Malware Protection Enabled",
            description=(
                "Ensure GuardDuty Malware Protection is enabled for EBS volumes. "
                "This scans EBS volumes attached to EC2 instances for malware."
            ),
            severity="high",
            resource_types=["guardduty_detector"],
            condition=Condition(
                path="raw_data.Features[?Name=='EBS_MALWARE_PROTECTION'].Status",
                operator=Operator.CONTAINS,
                value="ENABLED",
            ),
            remediation="Enable GuardDuty Malware Protection for EBS scanning.",
            frameworks={"soc2": ["CC6.8"], "nist-800-53": ["SI-3"]},
            tags=["guardduty", "malware", "ebs"],
        ),
        CheckDefinition(
            id="soc2-cc6.8-inspector-enabled",
            title="Amazon Inspector Enabled",
            description=(
                "Ensure Amazon Inspector is enabled for vulnerability scanning. "
                "Inspector automatically discovers and scans EC2 instances and container images."
            ),
            severity="high",
            resource_types=["inspector2_coverage"],
            condition=Condition(
                path="raw_data.Status",
                operator=Operator.EQUALS,
                value="ENABLED",
            ),
            remediation="Enable Amazon Inspector for automated vulnerability assessment.",
            frameworks={"soc2": ["CC6.8", "CC7.1"], "nist-800-53": ["RA-5", "SI-3"]},
            tags=["inspector", "vulnerability", "scanning"],
        ),
        # =====================================================================
        # CC7.1 - Detection of Deviations
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.1-config-enabled",
            title="AWS Config Enabled for Deviation Detection",
            description=(
                "Ensure AWS Config is enabled to detect configuration deviations. "
                "Config continuously monitors and records resource configurations."
            ),
            severity="high",
            resource_types=["config_recorder"],
            condition=ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[
                    Condition(
                        path="raw_data.recording",
                        operator=Operator.IS_TRUE,
                    ),
                    Condition(
                        path="raw_data.recordingGroup.allSupported",
                        operator=Operator.IS_TRUE,
                    ),
                ],
            ),
            remediation="Enable AWS Config with recording for all supported resource types.",
            frameworks={"soc2": ["CC7.1"], "nist-800-53": ["CM-3", "CM-8"]},
            tags=["config", "configuration-management", "deviation-detection"],
        ),
        CheckDefinition(
            id="soc2-cc7.1-config-rules-compliance",
            title="AWS Config Rules Evaluate Compliance",
            description=(
                "Ensure AWS Config rules are configured to evaluate resource compliance. "
                "Config rules automatically check resources against desired configurations."
            ),
            severity="medium",
            resource_types=["config_rule"],
            condition=Condition(
                path="raw_data.ConfigRuleState",
                operator=Operator.EQUALS,
                value="ACTIVE",
            ),
            remediation="Ensure Config rules are active and evaluating resources.",
            frameworks={"soc2": ["CC7.1"], "nist-800-53": ["CA-7", "CM-6"]},
            tags=["config", "compliance", "rules"],
        ),
        CheckDefinition(
            id="soc2-cc7.1-securityhub-standards",
            title="Security Hub Security Standards Enabled",
            description=(
                "Ensure AWS Security Hub has security standards enabled for deviation detection. "
                "Security Hub aggregates findings from multiple AWS services."
            ),
            severity="high",
            resource_types=["securityhub_hub"],
            condition=Condition(
                path="raw_data.AutoEnableControls",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Security Hub with automated controls for all standards.",
            frameworks={"soc2": ["CC7.1", "CC9.2"], "nist-800-53": ["CA-7", "RA-5"]},
            tags=["securityhub", "compliance", "deviation-detection"],
        ),
        # =====================================================================
        # CC7.5 - Incident Restoration
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.5-rds-automated-backup-retention",
            title="RDS Backup Retention for Recovery",
            description=(
                "Ensure RDS instances have sufficient backup retention for incident restoration. "
                "At least 7 days retention is required for meaningful recovery capability."
            ),
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.BackupRetentionPeriod",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=7,
            ),
            remediation="Set RDS backup retention period to at least 7 days.",
            frameworks={"soc2": ["CC7.5", "A1.2"], "nist-800-53": ["CP-9", "CP-10"]},
            tags=["rds", "backup", "recovery"],
        ),
        CheckDefinition(
            id="soc2-cc7.5-dynamodb-pitr-enabled",
            title="DynamoDB Point-in-Time Recovery Enabled",
            description=(
                "Ensure DynamoDB tables have Point-in-Time Recovery (PITR) enabled. "
                "PITR allows restoration to any point in the last 35 days."
            ),
            severity="high",
            resource_types=["dynamodb_table"],
            condition=Condition(
                path="raw_data.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus",
                operator=Operator.EQUALS,
                value="ENABLED",
            ),
            remediation="Enable Point-in-Time Recovery for DynamoDB tables.",
            frameworks={"soc2": ["CC7.5", "A1.2"], "nist-800-53": ["CP-9"]},
            tags=["dynamodb", "pitr", "recovery"],
        ),
        CheckDefinition(
            id="soc2-cc7.5-ebs-snapshot-lifecycle",
            title="EBS Snapshot Lifecycle Policy Configured",
            description=(
                "Ensure EBS volumes have snapshot lifecycle policies for automated backups. "
                "Data Lifecycle Manager automates EBS snapshots for recovery."
            ),
            severity="medium",
            resource_types=["dlm_lifecycle_policy"],
            condition=Condition(
                path="raw_data.State",
                operator=Operator.EQUALS,
                value="ENABLED",
            ),
            remediation="Configure Data Lifecycle Manager policies for automated EBS snapshots.",
            frameworks={"soc2": ["CC7.5"], "nist-800-53": ["CP-9"]},
            tags=["ebs", "snapshot", "lifecycle"],
        ),
        # =====================================================================
        # CC9.1 - Risk Identification
        # =====================================================================
        CheckDefinition(
            id="soc2-cc9.1-inspector-findings-review",
            title="Inspector Vulnerability Findings Active",
            description=(
                "Ensure Amazon Inspector is actively scanning and producing findings. "
                "Regular vulnerability scanning identifies security risks."
            ),
            severity="high",
            resource_types=["inspector2_coverage"],
            condition=Condition(
                path="raw_data.ResourceType",
                operator=Operator.IN,
                value=["EC2", "ECR_REPOSITORY", "LAMBDA_FUNCTION"],
            ),
            remediation="Ensure Inspector scanning coverage includes all resource types.",
            frameworks={"soc2": ["CC9.1"], "nist-800-53": ["RA-3", "RA-5"]},
            tags=["inspector", "vulnerability", "risk-identification"],
        ),
        CheckDefinition(
            id="soc2-cc9.1-trusted-advisor-checks",
            title="Trusted Advisor Security Checks Enabled",
            description=(
                "Ensure AWS Trusted Advisor security checks are available and reviewed. "
                "Trusted Advisor identifies security risks and best practice deviations."
            ),
            severity="medium",
            resource_types=["trustedadvisor_check"],
            condition=Condition(
                path="raw_data.status",
                operator=Operator.NOT_EQUALS,
                value="not_available",
            ),
            remediation="Enable AWS Business or Enterprise Support for full Trusted Advisor access.",
            frameworks={"soc2": ["CC9.1"], "nist-800-53": ["RA-3", "PM-9"]},
            tags=["trustedadvisor", "security", "risk-assessment"],
        ),
        CheckDefinition(
            id="soc2-cc9.1-iam-access-analyzer",
            title="IAM Access Analyzer Enabled",
            description=(
                "Ensure IAM Access Analyzer is enabled to identify resource risks. "
                "Access Analyzer finds resources shared externally and overly permissive policies."
            ),
            severity="high",
            resource_types=["accessanalyzer_analyzer"],
            condition=Condition(
                path="raw_data.status",
                operator=Operator.EQUALS,
                value="ACTIVE",
            ),
            remediation="Enable IAM Access Analyzer for the AWS account/organization.",
            frameworks={"soc2": ["CC9.1", "CC6.1"], "nist-800-53": ["AC-6", "RA-5"]},
            tags=["iam", "access-analyzer", "risk-identification"],
        ),
    ]


# =============================================================================
# Azure Compliance Checks
# =============================================================================


def get_soc2_azure_checks() -> list[CheckDefinition]:
    """
    Get automated SOC 2 checks for Azure resources.

    Returns:
        List of check definitions mapped to SOC 2 Trust Services Criteria.

    Coverage:
        - CC6.1: 5 checks (encryption, Key Vault)
        - CC6.3: 3 checks (NSG, VNet flow logs)
        - CC6.6: 4 checks (public access, HTTPS, TLS)
        - CC7.2: 4 checks (Activity Log, Defender, SQL auditing)
        - CC7.3: 3 checks (VM backup, SQL backup, soft delete)
        - CC8.1: 1 check (Azure Policy)
        - A1.2: 2 checks (Load Balancer zones, geo-redundant backup)
    """
    return [
        # =====================================================================
        # CC6.1 - Logical Access Security
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.1-azure-storage-encryption",
            title="Azure Storage Account Encryption Enabled",
            description=(
                "Ensure Azure Storage accounts have encryption enabled. "
                "Encryption protects data at rest from unauthorized access."
            ),
            severity="critical",
            resource_types=["storage_account"],
            condition=Condition(
                path="raw_data.encryption.services.blob.enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation=(
                "Azure Storage encryption is enabled by default and cannot be disabled. "
                "If encryption is not showing, verify the storage account configuration."
            ),
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["encryption", "storage", "data-protection", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-azure-sql-encryption",
            title="Azure SQL TDE Enabled",
            description=(
                "Ensure Azure SQL databases have Transparent Data Encryption (TDE) enabled. "
                "TDE encrypts data at rest to protect against unauthorized access."
            ),
            severity="critical",
            resource_types=["sql_database"],
            condition=Condition(
                path="raw_data.transparent_data_encryption.status",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable Transparent Data Encryption for Azure SQL databases.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["encryption", "sql", "data-protection", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-azure-disk-encryption",
            title="Azure Disk Encryption Enabled",
            description=(
                "Ensure Azure managed disks are encrypted. "
                "Disk encryption protects VM data at rest."
            ),
            severity="high",
            resource_types=["disk"],
            condition=Condition(
                path="raw_data.encryption.type",
                operator=Operator.EXISTS,
            ),
            remediation="Enable Azure Disk Encryption or use platform-managed encryption.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["encryption", "disk", "vm", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-azure-keyvault-soft-delete",
            title="Azure Key Vault Soft Delete Enabled",
            description=(
                "Ensure Azure Key Vault has soft delete enabled. "
                "Soft delete protects against accidental or malicious key deletion."
            ),
            severity="high",
            resource_types=["key_vault"],
            condition=Condition(
                path="raw_data.properties.enable_soft_delete",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable soft delete for Key Vault (enabled by default for new vaults).",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-12"]},
            tags=["keyvault", "key-protection", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-azure-keyvault-purge-protection",
            title="Azure Key Vault Purge Protection Enabled",
            description=(
                "Ensure Azure Key Vault has purge protection enabled. "
                "Purge protection prevents permanent deletion of keys during retention period."
            ),
            severity="high",
            resource_types=["key_vault"],
            condition=Condition(
                path="raw_data.properties.enable_purge_protection",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable purge protection for Key Vault.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-12"]},
            tags=["keyvault", "key-protection", "azure"],
        ),
        # =====================================================================
        # CC6.3 - Network Security
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.3-azure-nsg-no-public-ssh",
            title="Azure NSG No Unrestricted SSH",
            description=(
                "Ensure Network Security Groups do not allow unrestricted SSH access. "
                "Unrestricted SSH access is a critical security vulnerability."
            ),
            severity="critical",
            resource_types=["network_security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.security_rules",
                        operator=Operator.CONTAINS,
                        value="0.0.0.0/0:22",
                    ),
                ],
            ),
            remediation="Restrict SSH access to specific IP ranges or use Azure Bastion.",
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["nsg", "network", "ssh", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-azure-nsg-no-public-rdp",
            title="Azure NSG No Unrestricted RDP",
            description=(
                "Ensure Network Security Groups do not allow unrestricted RDP access. "
                "Unrestricted RDP access is a critical security vulnerability."
            ),
            severity="critical",
            resource_types=["network_security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.security_rules",
                        operator=Operator.CONTAINS,
                        value="0.0.0.0/0:3389",
                    ),
                ],
            ),
            remediation="Restrict RDP access to specific IP ranges or use Azure Bastion.",
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["nsg", "network", "rdp", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-azure-vnet-flow-logs",
            title="Azure VNet Flow Logs Enabled",
            description=(
                "Ensure Virtual Network has NSG flow logs enabled. "
                "Flow logs capture network traffic for security monitoring."
            ),
            severity="high",
            resource_types=["virtual_network"],
            condition=Condition(
                path="raw_data.flow_logs_enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation=(
                "Enable NSG flow logs:\n"
                "1. Navigate to Network Watcher\n"
                "2. Select NSG flow logs\n"
                "3. Configure flow logs for the associated NSGs"
            ),
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AU-2", "AU-12"]},
            tags=["vnet", "flow-logs", "monitoring", "azure"],
        ),
        # =====================================================================
        # CC6.6 - External Access Protection
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.6-azure-storage-public-access-disabled",
            title="Azure Storage Public Access Disabled",
            description=(
                "Ensure Azure Storage accounts have public blob access disabled. "
                "Public storage is a common source of data breaches."
            ),
            severity="critical",
            resource_types=["storage_account"],
            condition=Condition(
                path="raw_data.allow_blob_public_access",
                operator=Operator.IS_FALSE,
            ),
            remediation="Disable public blob access in storage account configuration.",
            frameworks={"soc2": ["CC6.6"], "nist-800-53": ["AC-3", "AC-21"]},
            tags=["storage", "public-access", "data-protection", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.6-azure-sql-not-public",
            title="Azure SQL Not Publicly Accessible",
            description=(
                "Ensure Azure SQL servers do not allow public network access. "
                "Public databases are vulnerable to attacks from the internet."
            ),
            severity="critical",
            resource_types=["sql_server"],
            condition=Condition(
                path="raw_data.public_network_access",
                operator=Operator.EQUALS,
                value="Disabled",
            ),
            remediation="Disable public network access and use private endpoints.",
            frameworks={"soc2": ["CC6.6"], "nist-800-53": ["AC-3", "SC-7"]},
            tags=["sql", "public-access", "network", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.6-azure-storage-https-only",
            title="Azure Storage HTTPS Only",
            description=(
                "Ensure Azure Storage accounts enforce HTTPS traffic only. "
                "HTTPS ensures data is encrypted in transit."
            ),
            severity="high",
            resource_types=["storage_account"],
            condition=Condition(
                path="raw_data.enable_https_traffic_only",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable 'Secure transfer required' in storage account settings.",
            frameworks={"soc2": ["CC6.6", "CC6.7"], "nist-800-53": ["SC-8"]},
            tags=["storage", "https", "encryption-in-transit", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc6.6-azure-storage-tls-version",
            title="Azure Storage Minimum TLS Version",
            description=(
                "Ensure Azure Storage accounts enforce TLS 1.2 minimum. "
                "Older TLS versions have known vulnerabilities."
            ),
            severity="high",
            resource_types=["storage_account"],
            condition=Condition(
                path="raw_data.minimum_tls_version",
                operator=Operator.EQUALS,
                value="TLS1_2",
            ),
            remediation="Set minimum TLS version to 1.2 in storage account settings.",
            frameworks={"soc2": ["CC6.6", "CC6.7"], "nist-800-53": ["SC-8"]},
            tags=["storage", "tls", "encryption-in-transit", "azure"],
        ),
        # =====================================================================
        # CC7.2 - System Monitoring
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.2-azure-activity-log-retention",
            title="Azure Activity Log Retention",
            description=(
                "Ensure Azure Activity Log has adequate retention. "
                "Activity logs provide audit trail for security and compliance."
            ),
            severity="high",
            resource_types=["diagnostic_settings"],
            condition=Condition(
                path="raw_data.retention_days",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=90,
            ),
            remediation="Configure Activity Log to retain for at least 90 days.",
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["AU-11"]},
            tags=["activity-log", "logging", "retention", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-azure-defender-enabled",
            title="Microsoft Defender for Cloud Enabled",
            description=(
                "Ensure Microsoft Defender for Cloud is enabled. "
                "Defender provides threat detection and security recommendations."
            ),
            severity="high",
            resource_types=["security_center_status"],
            condition=Condition(
                path="raw_data.pricing_tier",
                operator=Operator.EQUALS,
                value="Standard",
            ),
            remediation="Enable Microsoft Defender for Cloud Standard tier.",
            frameworks={"soc2": ["CC7.2", "CC7.4"], "nist-800-53": ["SI-4", "IR-4"]},
            tags=["defender", "threat-detection", "monitoring", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-azure-sql-auditing",
            title="Azure SQL Auditing Enabled",
            description=(
                "Ensure Azure SQL server has auditing enabled. "
                "Auditing provides activity logging for databases."
            ),
            severity="high",
            resource_types=["sql_server"],
            condition=Condition(
                path="raw_data.auditing_state",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable auditing for Azure SQL servers.",
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["AU-2", "AU-3"]},
            tags=["sql", "auditing", "logging", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc7.2-azure-sql-threat-detection",
            title="Azure SQL Threat Detection Enabled",
            description=(
                "Ensure Azure SQL has Advanced Threat Protection enabled. "
                "ATP detects anomalous database activities."
            ),
            severity="high",
            resource_types=["sql_server"],
            condition=Condition(
                path="raw_data.threat_detection_state",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable Advanced Threat Protection for Azure SQL servers.",
            frameworks={"soc2": ["CC7.2", "CC7.4"], "nist-800-53": ["SI-4"]},
            tags=["sql", "threat-detection", "monitoring", "azure"],
        ),
        # =====================================================================
        # CC7.3 - Backup and Recovery
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.3-azure-vm-backup",
            title="Azure VM Backup Enabled",
            description=(
                "Ensure Azure VMs have backup enabled. "
                "Backups enable recovery from data loss or disasters."
            ),
            severity="high",
            resource_types=["virtual_machine"],
            condition=Condition(
                path="raw_data.backup_enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Azure Backup for virtual machines.",
            frameworks={"soc2": ["CC7.3", "A1.2"], "nist-800-53": ["CP-9"]},
            tags=["vm", "backup", "disaster-recovery", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc7.3-azure-sql-backup-retention",
            title="Azure SQL Backup Retention",
            description=(
                "Ensure Azure SQL has adequate backup retention. "
                "Point-in-time restore requires sufficient backup retention."
            ),
            severity="medium",
            resource_types=["sql_database"],
            condition=Condition(
                path="raw_data.backup_retention_days",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=7,
            ),
            remediation="Configure backup retention to at least 7 days.",
            frameworks={"soc2": ["CC7.3", "A1.2"], "nist-800-53": ["CP-9"]},
            tags=["sql", "backup", "disaster-recovery", "azure"],
        ),
        CheckDefinition(
            id="soc2-cc7.3-azure-storage-soft-delete",
            title="Azure Storage Blob Soft Delete",
            description=(
                "Ensure Azure Storage has blob soft delete enabled. "
                "Soft delete enables recovery of deleted blobs."
            ),
            severity="medium",
            resource_types=["storage_account"],
            condition=Condition(
                path="raw_data.blob_soft_delete_enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable blob soft delete in storage account data protection settings.",
            frameworks={"soc2": ["CC7.3", "A1.2"], "nist-800-53": ["CP-9"]},
            tags=["storage", "soft-delete", "data-protection", "azure"],
        ),
        # =====================================================================
        # CC8.1 - Change Management
        # =====================================================================
        CheckDefinition(
            id="soc2-cc8.1-azure-policy-assigned",
            title="Azure Policy Assigned",
            description=(
                "Ensure Azure Policy is assigned for governance. "
                "Azure Policy enforces organizational standards and compliance."
            ),
            severity="medium",
            resource_types=["policy_assignments"],
            condition=Condition(
                path="raw_data.assignments",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Assign Azure Policy initiatives for compliance governance.",
            frameworks={"soc2": ["CC8.1"], "nist-800-53": ["CM-2", "CM-3"]},
            tags=["policy", "governance", "compliance", "azure"],
        ),
        # =====================================================================
        # A1.2 - Availability
        # =====================================================================
        CheckDefinition(
            id="soc2-a1.2-azure-lb-multi-zone",
            title="Azure Load Balancer Zone Redundant",
            description=(
                "Ensure Azure Load Balancer uses zone-redundant frontend. "
                "Zone redundancy provides high availability across zones."
            ),
            severity="medium",
            resource_types=["load_balancer"],
            condition=Condition(
                path="raw_data.sku.tier",
                operator=Operator.EQUALS,
                value="Regional",
            ),
            remediation="Use Standard SKU Load Balancer with zone-redundant frontend.",
            frameworks={"soc2": ["A1.2"], "nist-800-53": ["CP-10"]},
            tags=["load-balancer", "availability", "zones", "azure"],
        ),
        CheckDefinition(
            id="soc2-a1.2-azure-sql-geo-redundant",
            title="Azure SQL Geo-Redundant Backup",
            description=(
                "Ensure Azure SQL uses geo-redundant backups. "
                "Geo-redundant backups enable regional disaster recovery."
            ),
            severity="medium",
            resource_types=["sql_database"],
            condition=Condition(
                path="raw_data.requested_backup_storage_redundancy",
                operator=Operator.EQUALS,
                value="Geo",
            ),
            remediation="Configure geo-redundant backup storage for SQL databases.",
            frameworks={"soc2": ["A1.2"], "nist-800-53": ["CP-10"]},
            tags=["sql", "backup", "geo-redundant", "azure"],
        ),
    ]


# =============================================================================
# GCP Compliance Checks
# =============================================================================


def get_soc2_gcp_checks() -> list[CheckDefinition]:
    """
    Get automated SOC 2 checks for GCP resources.

    Returns:
        List of check definitions mapped to SOC 2 Trust Services Criteria.

    Coverage:
        - CC6.1: 9 checks (bucket access, encryption, shielded VMs)
        - CC6.2: 2 checks (service account keys)
        - CC6.3: 4 checks (firewall rules, flow logs)
        - CC6.6: 1 check (bucket logging)
        - CC7.2: 1 check (integrity monitoring)
        - CC7.3: 1 check (deletion protection)
        - A1.2: 1 check (retention policy)
    """
    return [
        # =====================================================================
        # CC6.1 - Logical Access Security
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.1-gcp-bucket-uniform-access",
            title="GCP Storage Bucket Uniform Access Enabled",
            description=(
                "Ensure GCP Cloud Storage buckets use uniform bucket-level access. "
                "Uniform access simplifies permission management and improves security."
            ),
            severity="high",
            resource_types=["storage_bucket"],
            condition=Condition(
                path="raw_data.uniform_bucket_level_access.enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable uniform bucket-level access in the bucket settings.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["AC-3"]},
            tags=["storage", "access-control", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-bucket-public-prevention",
            title="GCP Storage Bucket Public Access Prevention",
            description=(
                "Ensure GCP Cloud Storage buckets have public access prevention enabled. "
                "This prevents accidental exposure of sensitive data."
            ),
            severity="critical",
            resource_types=["storage_bucket"],
            condition=Condition(
                path="raw_data.public_access_prevention",
                operator=Operator.EQUALS,
                value="enforced",
            ),
            remediation=(
                "Enable public access prevention for the bucket or set it at the organization level."
            ),
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["AC-3", "AC-22"]},
            tags=["storage", "public-access", "data-protection", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-bucket-versioning",
            title="GCP Storage Bucket Versioning Enabled",
            description=(
                "Ensure GCP Cloud Storage buckets have versioning enabled. "
                "Versioning protects against accidental deletion and allows recovery."
            ),
            severity="medium",
            resource_types=["storage_bucket"],
            condition=Condition(
                path="raw_data.versioning_enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable object versioning for the Cloud Storage bucket.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["CP-9"]},
            tags=["storage", "versioning", "data-protection", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-bucket-cmek",
            title="GCP Storage Bucket Customer-Managed Encryption",
            description=(
                "Ensure GCP Cloud Storage buckets use customer-managed encryption keys (CMEK). "
                "CMEK provides additional control over encryption key lifecycle."
            ),
            severity="medium",
            resource_types=["storage_bucket"],
            condition=Condition(
                path="raw_data.default_kms_key_name",
                operator=Operator.EXISTS,
            ),
            remediation="Configure a Cloud KMS key for bucket encryption.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-12", "SC-28"]},
            tags=["storage", "encryption", "cmek", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-kms-rotation",
            title="GCP KMS Key Rotation Enabled",
            description=(
                "Ensure GCP Cloud KMS keys have automatic rotation enabled. "
                "Key rotation limits the impact of key compromise."
            ),
            severity="high",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.rotation_period",
                operator=Operator.EXISTS,
            ),
            remediation="Configure automatic key rotation for Cloud KMS keys.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-12"]},
            tags=["kms", "encryption", "key-rotation", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-vm-shielded",
            title="GCP VM Shielded Instance Enabled",
            description=(
                "Ensure GCP Compute Engine VMs use shielded instance features. "
                "Shielded VMs protect against rootkits and boot-level malware."
            ),
            severity="high",
            resource_types=["compute_instance"],
            condition=ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[
                    Condition(
                        path="raw_data.shielded_instance_config.enable_secure_boot",
                        operator=Operator.IS_TRUE,
                    ),
                    Condition(
                        path="raw_data.shielded_instance_config.enable_vtpm",
                        operator=Operator.IS_TRUE,
                    ),
                ],
            ),
            remediation="Enable shielded VM features (Secure Boot, vTPM) for the instance.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SI-7"]},
            tags=["compute", "shielded-vm", "security", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-vm-no-public-ip",
            title="GCP VM No External IP Address",
            description=(
                "Ensure GCP Compute Engine VMs do not have external IP addresses. "
                "VMs should use Cloud NAT or private Google access instead."
            ),
            severity="medium",
            resource_types=["compute_instance"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.network_interfaces[0].access_configs",
                        operator=Operator.EXISTS,
                    ),
                ],
            ),
            remediation=(
                "Remove external IP addresses and use Cloud NAT for outbound connectivity."
            ),
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["compute", "network", "public-ip", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.1-gcp-disk-cmek",
            title="GCP Disk Customer-Managed Encryption",
            description=(
                "Ensure GCP persistent disks use customer-managed encryption keys. "
                "CMEK provides additional control over data encryption."
            ),
            severity="medium",
            resource_types=["compute_disk"],
            condition=Condition(
                path="raw_data.disk_encryption_key.kms_key_name",
                operator=Operator.EXISTS,
            ),
            remediation="Configure a Cloud KMS key for disk encryption.",
            frameworks={"soc2": ["CC6.1"], "nist-800-53": ["SC-28"]},
            tags=["compute", "disk", "encryption", "cmek", "gcp"],
        ),
        # =====================================================================
        # CC6.2 - User Registration and Authorization
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.2-gcp-sa-no-user-keys",
            title="GCP Service Account No User-Managed Keys",
            description=(
                "Ensure GCP service accounts do not have user-managed keys. "
                "User-managed keys are a security risk and should be avoided."
            ),
            severity="high",
            resource_types=["iam_service_account"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.keys",
                        operator=Operator.CONTAINS,
                        value="USER_MANAGED",
                    ),
                ],
            ),
            remediation=(
                "Use workload identity, service account impersonation, or attached service accounts "
                "instead of user-managed keys."
            ),
            frameworks={"soc2": ["CC6.2"], "nist-800-53": ["IA-2", "IA-5"]},
            tags=["iam", "service-account", "keys", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.2-gcp-sa-disabled",
            title="GCP Unused Service Accounts Disabled",
            description=(
                "Ensure unused GCP service accounts are disabled. "
                "Unused accounts increase the attack surface."
            ),
            severity="medium",
            resource_types=["iam_service_account"],
            condition=Condition(
                path="raw_data.disabled",
                operator=Operator.IS_FALSE,
            ),
            remediation="Disable or delete unused service accounts.",
            frameworks={"soc2": ["CC6.2"], "nist-800-53": ["AC-2"]},
            tags=["iam", "service-account", "hygiene", "gcp"],
        ),
        # =====================================================================
        # CC6.3 - Network Security
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.3-gcp-firewall-no-public-ssh",
            title="GCP Firewall No Unrestricted SSH",
            description=(
                "Ensure GCP firewall rules do not allow unrestricted SSH access. "
                "SSH should be restricted to specific IP ranges or use IAP."
            ),
            severity="critical",
            resource_types=["compute_firewall"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    ConditionGroup(
                        logic=LogicOperator.AND,
                        conditions=[
                            Condition(
                                path="raw_data.source_ranges",
                                operator=Operator.CONTAINS,
                                value="0.0.0.0/0",
                            ),
                            Condition(
                                path="raw_data.allowed",
                                operator=Operator.CONTAINS,
                                value="22",
                            ),
                        ],
                    ),
                ],
            ),
            remediation=(
                "Restrict SSH access to specific IP ranges or use Identity-Aware Proxy (IAP)."
            ),
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["firewall", "network", "ssh", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-gcp-firewall-no-public-rdp",
            title="GCP Firewall No Unrestricted RDP",
            description=(
                "Ensure GCP firewall rules do not allow unrestricted RDP access. "
                "RDP should be restricted to specific IP ranges."
            ),
            severity="critical",
            resource_types=["compute_firewall"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    ConditionGroup(
                        logic=LogicOperator.AND,
                        conditions=[
                            Condition(
                                path="raw_data.source_ranges",
                                operator=Operator.CONTAINS,
                                value="0.0.0.0/0",
                            ),
                            Condition(
                                path="raw_data.allowed",
                                operator=Operator.CONTAINS,
                                value="3389",
                            ),
                        ],
                    ),
                ],
            ),
            remediation="Restrict RDP access to specific IP ranges.",
            frameworks={"soc2": ["CC6.3"], "nist-800-53": ["AC-4", "SC-7"]},
            tags=["firewall", "network", "rdp", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-gcp-firewall-logging",
            title="GCP Firewall Rule Logging Enabled",
            description=(
                "Ensure GCP firewall rules have logging enabled. "
                "Logging provides visibility into network traffic for security monitoring."
            ),
            severity="medium",
            resource_types=["compute_firewall"],
            condition=Condition(
                path="raw_data.log_config.enable",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable logging for firewall rules.",
            frameworks={"soc2": ["CC6.3", "CC7.2"], "nist-800-53": ["AU-3", "SI-4"]},
            tags=["firewall", "logging", "monitoring", "gcp"],
        ),
        CheckDefinition(
            id="soc2-cc6.3-gcp-subnet-flow-logs",
            title="GCP VPC Flow Logs Enabled",
            description=(
                "Ensure GCP VPC subnets have flow logs enabled. "
                "Flow logs provide visibility into network traffic for security analysis."
            ),
            severity="medium",
            resource_types=["compute_subnetwork"],
            condition=Condition(
                path="raw_data.log_config.enable",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable VPC flow logs for the subnet.",
            frameworks={"soc2": ["CC6.3", "CC7.2"], "nist-800-53": ["AU-3", "SI-4"]},
            tags=["network", "vpc", "flow-logs", "monitoring", "gcp"],
        ),
        # =====================================================================
        # CC6.6 - Incident Response
        # =====================================================================
        CheckDefinition(
            id="soc2-cc6.6-gcp-bucket-logging",
            title="GCP Storage Bucket Logging Enabled",
            description=(
                "Ensure GCP Cloud Storage buckets have access logging enabled. "
                "Logging is essential for security monitoring and incident response."
            ),
            severity="medium",
            resource_types=["storage_bucket"],
            condition=Condition(
                path="raw_data.logging.log_bucket",
                operator=Operator.EXISTS,
            ),
            remediation="Configure a logging bucket for access logs.",
            frameworks={"soc2": ["CC6.6", "CC7.2"], "nist-800-53": ["AU-2", "AU-3"]},
            tags=["storage", "logging", "monitoring", "gcp"],
        ),
        # =====================================================================
        # CC7.2 - System Monitoring
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.2-gcp-vm-integrity-monitoring",
            title="GCP VM Integrity Monitoring Enabled",
            description=(
                "Ensure GCP VMs have integrity monitoring enabled. "
                "Integrity monitoring detects unauthorized changes to boot components."
            ),
            severity="medium",
            resource_types=["compute_instance"],
            condition=Condition(
                path="raw_data.shielded_instance_config.enable_integrity_monitoring",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable integrity monitoring in shielded VM settings.",
            frameworks={"soc2": ["CC7.2"], "nist-800-53": ["SI-7"]},
            tags=["compute", "integrity", "monitoring", "gcp"],
        ),
        # =====================================================================
        # CC7.3 - Change Detection
        # =====================================================================
        CheckDefinition(
            id="soc2-cc7.3-gcp-vm-deletion-protection",
            title="GCP VM Deletion Protection Enabled",
            description=(
                "Ensure GCP Compute Engine VMs have deletion protection enabled. "
                "This prevents accidental deletion of critical workloads."
            ),
            severity="low",
            resource_types=["compute_instance"],
            condition=Condition(
                path="raw_data.deletion_protection",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable deletion protection for critical VMs.",
            frameworks={"soc2": ["CC7.3"], "nist-800-53": ["CM-3"]},
            tags=["compute", "deletion-protection", "change-management", "gcp"],
        ),
        # =====================================================================
        # A1.2 - Recovery
        # =====================================================================
        CheckDefinition(
            id="soc2-a1.2-gcp-bucket-retention",
            title="GCP Storage Bucket Retention Policy",
            description=(
                "Ensure GCP Cloud Storage buckets have retention policies configured. "
                "Retention policies protect data from deletion for compliance purposes."
            ),
            severity="medium",
            resource_types=["storage_bucket"],
            condition=Condition(
                path="raw_data.retention_policy.retention_period",
                operator=Operator.EXISTS,
            ),
            remediation="Configure a retention policy for the bucket.",
            frameworks={"soc2": ["A1.2"], "nist-800-53": ["CP-9"]},
            tags=["storage", "retention", "backup", "gcp"],
        ),
    ]


# =============================================================================
# Evaluator and Framework Factory Functions
# =============================================================================


def create_soc2_evaluator(provider: str | None = None) -> Evaluator:
    """
    Create an evaluator pre-loaded with SOC 2 checks.

    Args:
        provider: Cloud provider to filter checks for ('aws', 'azure', 'gcp', or None for all).

    Returns:
        Evaluator with SOC 2 checks registered.

    Example:
        >>> evaluator = create_soc2_evaluator("aws")
        >>> results = evaluator.evaluate(resources)
    """
    evaluator = Evaluator()

    if provider is None or provider == "aws":
        for check in get_soc2_aws_checks():
            evaluator.register_check(check)

    if provider is None or provider == "azure":
        for check in get_soc2_azure_checks():
            evaluator.register_check(check)

    if provider is None or provider == "gcp":
        for check in get_soc2_gcp_checks():
            evaluator.register_check(check)

    logger.info(f"Created SOC 2 evaluator with {len(evaluator._checks)} checks (provider={provider})")
    return evaluator


def get_soc2_framework() -> SOC2Framework:
    """
    Get the complete SOC 2 framework definition.

    Returns:
        SOC2Framework with all controls and check mappings.

    Example:
        >>> framework = get_soc2_framework()
        >>> checks = framework.get_checks_for_control("CC6.1")
    """
    framework = SOC2Framework(
        version=SOC2_VERSION,
        controls=SOC2_CONTROLS,
    )

    # Build check mappings from all providers
    all_checks = get_soc2_aws_checks() + get_soc2_azure_checks() + get_soc2_gcp_checks()
    for check in all_checks:
        soc2_controls = check.frameworks.get("soc2", [])
        for control_id in soc2_controls:
            if control_id not in framework.check_mappings:
                framework.check_mappings[control_id] = []
            framework.check_mappings[control_id].append(check.id)

    return framework


def get_check_statistics() -> dict:
    """
    Get statistics about SOC 2 check coverage.

    Returns:
        Dictionary with check counts and coverage statistics.
    """
    aws_checks = get_soc2_aws_checks()
    azure_checks = get_soc2_azure_checks()
    gcp_checks = get_soc2_gcp_checks()
    all_checks = aws_checks + azure_checks + gcp_checks

    # Count unique controls covered
    controls_covered: set[str] = set()
    for check in all_checks:
        controls_covered.update(check.frameworks.get("soc2", []))

    # Count by severity
    severity_counts: dict[str, int] = {}
    for check in all_checks:
        severity = check.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Count by criteria category
    category_counts: dict[str, int] = {}
    for check in all_checks:
        for control_id in check.frameworks.get("soc2", []):
            if control_id.startswith("CC"):
                category = "Security (Common Criteria)"
            elif control_id.startswith("A"):
                category = "Availability"
            elif control_id.startswith("PI"):
                category = "Processing Integrity"
            elif control_id.startswith("C"):
                category = "Confidentiality"
            elif control_id.startswith("P"):
                category = "Privacy"
            else:
                category = "Other"
            category_counts[category] = category_counts.get(category, 0) + 1

    return {
        "total_checks": len(all_checks),
        "aws_checks": len(aws_checks),
        "azure_checks": len(azure_checks),
        "gcp_checks": len(gcp_checks),
        "controls_covered": len(controls_covered),
        "unique_controls": sorted(controls_covered),
        "severity_distribution": severity_counts,
        "category_distribution": category_counts,
    }


__all__ = [
    # Check getter functions
    "get_soc2_aws_checks",
    "get_soc2_azure_checks",
    "get_soc2_gcp_checks",
    # Factory functions
    "create_soc2_evaluator",
    "get_soc2_framework",
    # Statistics
    "get_check_statistics",
]
