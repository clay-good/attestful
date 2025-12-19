"""
Automated compliance checks for NIST 800-53 controls.

Provides check definitions for AWS, Azure, and GCP cloud resources
mapped to NIST 800-53 controls.

These checks use the Attestful evaluator engine to assess cloud resources
against NIST 800-53 requirements.
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
from attestful.frameworks.nist_800_53.controls import (
    NIST_800_53_CONTROLS,
    NIST_800_53_VERSION,
    NIST80053Framework,
)

logger = get_logger(__name__)


# =============================================================================
# AWS Compliance Checks
# =============================================================================


def get_nist_800_53_aws_checks() -> list[CheckDefinition]:
    """
    Get AWS compliance checks mapped to NIST 800-53 controls.

    Returns:
        List of CheckDefinition objects for AWS resources.
    """
    return [
        # ---------------------------------------------------------------------------
        # AC-2: Account Management
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ac-2-1",
            title="IAM users should have MFA enabled",
            description="Multi-factor authentication adds an extra layer of protection for user accounts.",
            severity="high",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.MFADevices",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable MFA for all IAM users in the AWS Console or using aws iam enable-mfa-device.",
            frameworks={"nist-800-53": ["AC-2", "IA-2", "IA-2(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-ac-2-2",
            title="IAM access keys should be rotated within 90 days",
            description="Access key rotation limits the damage from compromised keys.",
            severity="medium",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.AccessKey1LastRotatedDays",
                operator=Operator.LESS_THAN,
                value=90,
            ),
            remediation="Rotate IAM access keys within 90 days using aws iam create-access-key and aws iam delete-access-key.",
            frameworks={"nist-800-53": ["AC-2", "IA-5"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-ac-2-3",
            title="IAM users with console access should have MFA",
            description="Console access should require MFA for additional security.",
            severity="high",
            resource_types=["iam_user"],
            condition=ConditionGroup(
                logic=LogicOperator.OR,
                conditions=[
                    Condition(
                        path="raw_data.PasswordEnabled",
                        operator=Operator.IS_FALSE,
                    ),
                    Condition(
                        path="raw_data.MFAActive",
                        operator=Operator.IS_TRUE,
                    ),
                ],
            ),
            remediation="Enable MFA for all IAM users with console password access.",
            frameworks={"nist-800-53": ["AC-2", "IA-2(1)", "IA-2(2)"]},
        ),

        # ---------------------------------------------------------------------------
        # AC-3: Access Enforcement / AC-6: Least Privilege
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ac-6-1",
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
            frameworks={"nist-800-53": ["AC-6", "AC-6(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-ac-6-2",
            title="IAM policies should not allow full administrative privileges",
            description="Policies with full * permissions violate least privilege.",
            severity="high",
            resource_types=["iam_policy"],
            condition=Condition(
                path="raw_data.AllowsFullAdmin",
                operator=Operator.IS_FALSE,
            ),
            remediation="Remove overly permissive policies and implement least privilege access.",
            frameworks={"nist-800-53": ["AC-6", "AC-6(1)", "AC-6(10)"]},
        ),

        # ---------------------------------------------------------------------------
        # AU-2/AU-3: Audit Logging
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-au-2-1",
            title="CloudTrail should be enabled and logging",
            description="CloudTrail provides audit logs for API calls across AWS services.",
            severity="high",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IsLogging",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable CloudTrail logging.",
            frameworks={"nist-800-53": ["AU-2", "AU-3", "AU-12"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-au-2-2",
            title="CloudTrail should be multi-region",
            description="Multi-region trails capture API activity across all AWS regions.",
            severity="high",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IsMultiRegionTrail",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable multi-region CloudTrail trail.",
            frameworks={"nist-800-53": ["AU-2", "AU-3"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-au-3-1",
            title="CloudTrail should log management events",
            description="Management events provide visibility into control plane operations.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IncludeManagementEvents",
                operator=Operator.IS_TRUE,
            ),
            remediation="Configure CloudTrail to log management events.",
            frameworks={"nist-800-53": ["AU-3", "AU-3(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-au-9-1",
            title="CloudTrail logs should be encrypted at rest with KMS",
            description="Encrypting CloudTrail logs protects sensitive audit information.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.KMSKeyId",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable KMS encryption for CloudTrail logs.",
            frameworks={"nist-800-53": ["AU-9", "SC-13", "SC-28"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-au-9-2",
            title="CloudTrail log file validation should be enabled",
            description="Log file validation ensures audit logs have not been tampered with.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.LogFileValidationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable log file validation for CloudTrail.",
            frameworks={"nist-800-53": ["AU-9"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-au-9-3",
            title="CloudTrail S3 bucket should block public access",
            description="CloudTrail logs should not be publicly accessible.",
            severity="critical",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.S3BucketPubliclyAccessible",
                operator=Operator.IS_FALSE,
            ),
            remediation="Enable S3 block public access for CloudTrail bucket.",
            frameworks={"nist-800-53": ["AU-9", "AC-3"]},
        ),

        # ---------------------------------------------------------------------------
        # CM-6: Configuration Settings / CM-7: Least Functionality
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-cm-6-1",
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
            frameworks={"nist-800-53": ["CM-6", "CM-7"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-cm-7-1",
            title="Security groups should not allow unrestricted SSH access",
            description="Unrestricted SSH access from the internet poses a security risk.",
            severity="high",
            resource_types=["security_group"],
            condition=Condition(
                path="raw_data.AllowsSSHFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict SSH access to specific IP ranges or use a bastion host.",
            frameworks={"nist-800-53": ["CM-7", "SC-7"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-cm-7-2",
            title="Security groups should not allow unrestricted RDP access",
            description="Unrestricted RDP access from the internet poses a security risk.",
            severity="high",
            resource_types=["security_group"],
            condition=Condition(
                path="raw_data.AllowsRDPFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict RDP access to specific IP ranges or use a bastion host.",
            frameworks={"nist-800-53": ["CM-7", "SC-7"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-cm-7-3",
            title="Default security groups should restrict all traffic",
            description="Default security groups should have no inbound or outbound rules.",
            severity="medium",
            resource_types=["security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.OR,
                conditions=[
                    Condition(
                        path="raw_data.GroupName",
                        operator=Operator.NOT_EQUALS,
                        value="default",
                    ),
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
            remediation="Remove all rules from default security groups.",
            frameworks={"nist-800-53": ["CM-7", "CM-7(1)"]},
        ),

        # ---------------------------------------------------------------------------
        # CM-8: System Component Inventory
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-cm-8-1",
            title="EC2 instances should be tagged for inventory tracking",
            description="Proper tagging supports system component inventory requirements.",
            severity="low",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.Tags",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Apply appropriate tags to all EC2 instances for inventory tracking.",
            frameworks={"nist-800-53": ["CM-8", "CM-8(1)"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-7: Boundary Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-sc-7-1",
            title="VPCs should have flow logs enabled",
            description="VPC flow logs capture information about IP traffic for security analysis.",
            severity="medium",
            resource_types=["vpc"],
            condition=Condition(
                path="raw_data.FlowLogsEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable VPC flow logs for all VPCs.",
            frameworks={"nist-800-53": ["SC-7", "AU-2", "SI-4"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-7-2",
            title="Network ACLs should not allow unrestricted ingress",
            description="Network ACLs should restrict inbound traffic.",
            severity="high",
            resource_types=["network_acl"],
            condition=Condition(
                path="raw_data.AllowsUnrestrictedIngress",
                operator=Operator.IS_FALSE,
            ),
            remediation="Configure network ACLs to restrict inbound traffic to known sources.",
            frameworks={"nist-800-53": ["SC-7", "SC-7(5)"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-8: Transmission Confidentiality and Integrity
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-sc-8-1",
            title="ELB listeners should use HTTPS/SSL",
            description="Load balancer listeners should use encrypted protocols.",
            severity="high",
            resource_types=["elb_listener"],
            condition=Condition(
                path="raw_data.Protocol",
                operator=Operator.IN,
                value=["HTTPS", "SSL", "TLS"],
            ),
            remediation="Configure ELB listeners to use HTTPS or SSL protocols.",
            frameworks={"nist-800-53": ["SC-8", "SC-8(1)", "SC-13"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-8-2",
            title="CloudFront distributions should require HTTPS",
            description="CloudFront should enforce HTTPS for viewer connections.",
            severity="high",
            resource_types=["cloudfront_distribution"],
            condition=Condition(
                path="raw_data.ViewerProtocolPolicy",
                operator=Operator.IN,
                value=["https-only", "redirect-to-https"],
            ),
            remediation="Configure CloudFront to require HTTPS for viewer connections.",
            frameworks={"nist-800-53": ["SC-8", "SC-8(1)"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-13/SC-28: Cryptographic Protection / Protection at Rest
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-sc-13-1",
            title="S3 buckets should have server-side encryption enabled",
            description="Server-side encryption protects data at rest in S3 buckets.",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.ServerSideEncryptionEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable default encryption on S3 buckets.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-13-2",
            title="EBS volumes should be encrypted",
            description="EBS encryption protects data at rest on EC2 volumes.",
            severity="high",
            resource_types=["ebs_volume"],
            condition=Condition(
                path="raw_data.Encrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for EBS volumes.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-13-3",
            title="RDS instances should be encrypted",
            description="RDS encryption protects data at rest in databases.",
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.StorageEncrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for RDS instances.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-13-4",
            title="S3 buckets should use KMS encryption",
            description="KMS encryption provides additional key management controls.",
            severity="medium",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.KMSMasterKeyID",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Configure S3 buckets to use KMS encryption.",
            frameworks={"nist-800-53": ["SC-13", "SC-12", "SC-28(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-13-5",
            title="EFS file systems should be encrypted",
            description="EFS encryption protects data at rest in file systems.",
            severity="high",
            resource_types=["efs_file_system"],
            condition=Condition(
                path="raw_data.Encrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for EFS file systems.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),

        # ---------------------------------------------------------------------------
        # SI-2: Flaw Remediation
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-si-2-1",
            title="RDS instances should have auto minor version upgrade enabled",
            description="Auto minor version upgrade ensures security patches are applied.",
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.AutoMinorVersionUpgrade",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable auto minor version upgrade for RDS instances.",
            frameworks={"nist-800-53": ["SI-2", "SI-2(2)"]},
        ),

        # ---------------------------------------------------------------------------
        # SI-4: System Monitoring
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-si-4-1",
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
            frameworks={"nist-800-53": ["SI-4", "IR-4"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-si-4-2",
            title="AWS Config should be enabled",
            description="AWS Config tracks resource configuration changes.",
            severity="medium",
            resource_types=["config_recorder"],
            condition=Condition(
                path="raw_data.Recording",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable AWS Config in all regions.",
            frameworks={"nist-800-53": ["SI-4", "CM-8"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-si-4-3",
            title="SecurityHub should be enabled",
            description="SecurityHub aggregates security findings from multiple sources.",
            severity="medium",
            resource_types=["securityhub_hub"],
            condition=Condition(
                path="raw_data.HubArn",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable AWS Security Hub.",
            frameworks={"nist-800-53": ["SI-4", "SI-4(2)", "AU-6"]},
        ),

        # ---------------------------------------------------------------------------
        # IA-5: Authenticator Management
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ia-5-1",
            title="IAM password policy should require minimum length of 14",
            description="Strong password length requirements protect against brute force attacks.",
            severity="medium",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.MinimumPasswordLength",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=14,
            ),
            remediation="Set IAM password policy minimum length to at least 14 characters.",
            frameworks={"nist-800-53": ["IA-5", "IA-5(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-ia-5-2",
            title="IAM password policy should require symbols",
            description="Complex passwords including symbols are harder to compromise.",
            severity="medium",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.RequireSymbols",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable symbol requirement in IAM password policy.",
            frameworks={"nist-800-53": ["IA-5", "IA-5(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-ia-5-3",
            title="IAM password policy should prevent password reuse",
            description="Password reuse prevention reduces risk from compromised credentials.",
            severity="medium",
            resource_types=["iam_password_policy"],
            condition=Condition(
                path="raw_data.PasswordReusePrevention",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=24,
            ),
            remediation="Set password reuse prevention to at least 24 previous passwords.",
            frameworks={"nist-800-53": ["IA-5", "IA-5(1)"]},
        ),

        # ---------------------------------------------------------------------------
        # AC-4: Information Flow Enforcement
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ac-4-1",
            title="VPC flow logs should be enabled",
            description="VPC flow logs capture information about IP traffic for information flow monitoring.",
            severity="medium",
            resource_types=["vpc"],
            condition=Condition(
                path="raw_data.FlowLogsEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable VPC Flow Logs for all VPCs.",
            frameworks={"nist-800-53": ["AC-4", "AU-12", "SI-4"]},
        ),

        # ---------------------------------------------------------------------------
        # AC-17: Remote Access
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ac-17-1",
            title="EC2 instances should not have public IP addresses unless required",
            description="Public IP addresses increase attack surface for remote access.",
            severity="medium",
            resource_types=["ec2_instance"],
            condition=ConditionGroup(
                logic=LogicOperator.OR,
                conditions=[
                    Condition(
                        path="raw_data.PublicIpAddress",
                        operator=Operator.IS_EMPTY,
                    ),
                    Condition(
                        path="tags.PublicFacing",
                        operator=Operator.EQUALS,
                        value="true",
                    ),
                ],
            ),
            remediation="Remove public IP addresses from non-public-facing EC2 instances.",
            frameworks={"nist-800-53": ["AC-17", "SC-7"]},
        ),

        # ---------------------------------------------------------------------------
        # CP-9: System Backup
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-cp-9-1",
            title="RDS instances should have automated backups enabled",
            description="Automated backups ensure data can be recovered in case of failure.",
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.BackupRetentionPeriod",
                operator=Operator.GREATER_THAN,
                value=0,
            ),
            remediation="Enable automated backups for RDS instances with appropriate retention period.",
            frameworks={"nist-800-53": ["CP-9", "CP-10"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-cp-9-2",
            title="EBS volumes should have snapshots",
            description="EBS snapshots provide point-in-time backup for recovery.",
            severity="medium",
            resource_types=["ebs_volume"],
            condition=Condition(
                path="raw_data.HasRecentSnapshot",
                operator=Operator.IS_TRUE,
            ),
            remediation="Create regular EBS volume snapshots or use AWS Backup.",
            frameworks={"nist-800-53": ["CP-9", "CP-9(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-cp-9-3",
            title="S3 buckets should have versioning enabled",
            description="S3 versioning enables recovery from unintended user actions or failures.",
            severity="medium",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Versioning.Status",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable versioning for S3 buckets.",
            frameworks={"nist-800-53": ["CP-9", "CP-10", "SI-12"]},
        ),

        # ---------------------------------------------------------------------------
        # CP-10: System Recovery and Reconstitution
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-cp-10-1",
            title="RDS instances should be deployed in multiple AZs",
            description="Multi-AZ deployment provides high availability and disaster recovery.",
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.MultiAZ",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Multi-AZ deployment for production RDS instances.",
            frameworks={"nist-800-53": ["CP-10", "CP-6", "CP-7"]},
        ),

        # ---------------------------------------------------------------------------
        # RA-5: Vulnerability Monitoring and Scanning
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ra-5-1",
            title="ECR repositories should have image scanning enabled",
            description="Image scanning identifies vulnerabilities in container images.",
            severity="high",
            resource_types=["ecr_repository"],
            condition=Condition(
                path="raw_data.ImageScanningConfiguration.ScanOnPush",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable scan on push for ECR repositories.",
            frameworks={"nist-800-53": ["RA-5", "SI-2"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-ra-5-2",
            title="Inspector should be enabled for EC2 instances",
            description="AWS Inspector performs automated security assessments.",
            severity="medium",
            resource_types=["inspector_assessment_target"],
            condition=Condition(
                path="raw_data.ResourceGroupArn",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable AWS Inspector and create assessment targets.",
            frameworks={"nist-800-53": ["RA-5", "RA-5(2)"]},
        ),

        # ---------------------------------------------------------------------------
        # SA-3: System Development Life Cycle
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-sa-3-1",
            title="CodeBuild projects should not have privileged mode enabled",
            description="Privileged mode grants container root access which should be avoided.",
            severity="high",
            resource_types=["codebuild_project"],
            condition=Condition(
                path="raw_data.Environment.PrivilegedMode",
                operator=Operator.IS_FALSE,
            ),
            remediation="Disable privileged mode for CodeBuild projects unless required.",
            frameworks={"nist-800-53": ["SA-3", "CM-7", "AC-6"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-5: Denial-of-Service Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-sc-5-1",
            title="WAF Web ACL should be associated with resources",
            description="AWS WAF provides protection against common web exploits and DDoS.",
            severity="medium",
            resource_types=["waf_web_acl"],
            condition=Condition(
                path="raw_data.AssociatedResources",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Associate WAF Web ACL with CloudFront, API Gateway, or ALB resources.",
            frameworks={"nist-800-53": ["SC-5", "SC-7", "SI-4"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-5-2",
            title="Shield Advanced should be enabled for critical resources",
            description="AWS Shield Advanced provides enhanced DDoS protection.",
            severity="low",
            resource_types=["shield_protection"],
            condition=Condition(
                path="raw_data.ProtectionArn",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable AWS Shield Advanced for critical resources.",
            frameworks={"nist-800-53": ["SC-5", "SC-5(2)"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-12: Cryptographic Key Establishment and Management
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-sc-12-1",
            title="KMS keys should have rotation enabled",
            description="Key rotation limits the amount of data encrypted with a single key.",
            severity="medium",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.KeyRotationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable automatic key rotation for KMS customer managed keys.",
            frameworks={"nist-800-53": ["SC-12", "SC-12(1)"]},
        ),
        CheckDefinition(
            id="nist-800-53-aws-sc-12-2",
            title="KMS keys should not be pending deletion",
            description="Keys pending deletion may cause data loss if deleted.",
            severity="high",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.KeyState",
                operator=Operator.NOT_EQUALS,
                value="PendingDeletion",
            ),
            remediation="Cancel deletion for required KMS keys or ensure data is re-encrypted.",
            frameworks={"nist-800-53": ["SC-12", "CP-9"]},
        ),

        # ---------------------------------------------------------------------------
        # IR-4: Incident Handling
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ir-4-1",
            title="SNS topics should be configured for security alerts",
            description="SNS topics enable notification of security events for incident response.",
            severity="medium",
            resource_types=["sns_topic"],
            condition=Condition(
                path="raw_data.Subscriptions",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Configure SNS topics with subscriptions for security alerting.",
            frameworks={"nist-800-53": ["IR-4", "IR-6", "SI-4"]},
        ),

        # ---------------------------------------------------------------------------
        # CA-7: Continuous Monitoring
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-aws-ca-7-1",
            title="CloudWatch alarms should be configured for critical metrics",
            description="CloudWatch alarms enable continuous monitoring of system state.",
            severity="medium",
            resource_types=["cloudwatch_alarm"],
            condition=Condition(
                path="raw_data.StateValue",
                operator=Operator.NOT_EQUALS,
                value="INSUFFICIENT_DATA",
            ),
            remediation="Configure CloudWatch alarms for critical security and performance metrics.",
            frameworks={"nist-800-53": ["CA-7", "SI-4", "AU-6"]},
        ),
    ]


# =============================================================================
# Azure Compliance Checks
# =============================================================================


def get_nist_800_53_azure_checks() -> list[CheckDefinition]:
    """
    Get Azure compliance checks mapped to NIST 800-53 controls.

    Returns:
        List of CheckDefinition objects for Azure resources.
    """
    return [
        # ---------------------------------------------------------------------------
        # AC-2: Account Management / IA-2: Identification and Authentication
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-azure-ac-2-1",
            title="Azure AD users should have MFA enabled",
            description="Multi-factor authentication protects against credential compromise.",
            severity="high",
            resource_types=["azure_ad_user"],
            condition=Condition(
                path="raw_data.StrongAuthenticationMethods",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable MFA for all Azure AD users.",
            frameworks={"nist-800-53": ["AC-2", "IA-2", "IA-2(1)"]},
        ),

        # ---------------------------------------------------------------------------
        # AU-2: Event Logging
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-azure-au-2-1",
            title="Azure Activity Log should be retained for at least 365 days",
            description="Activity logs provide audit trail of management operations.",
            severity="medium",
            resource_types=["azure_activity_log_profile"],
            condition=Condition(
                path="raw_data.RetentionDays",
                operator=Operator.GREATER_THAN_OR_EQUAL,
                value=365,
            ),
            remediation="Configure Activity Log retention to at least 365 days.",
            frameworks={"nist-800-53": ["AU-2", "AU-11"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-7: Boundary Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-azure-sc-7-1",
            title="Network Security Groups should not allow SSH from internet",
            description="SSH should not be accessible from the public internet.",
            severity="high",
            resource_types=["azure_nsg"],
            condition=Condition(
                path="raw_data.AllowsSSHFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Remove NSG rules allowing SSH from 0.0.0.0/0 or *.",
            frameworks={"nist-800-53": ["SC-7", "CM-7"]},
        ),
        CheckDefinition(
            id="nist-800-53-azure-sc-7-2",
            title="Network Security Groups should not allow RDP from internet",
            description="RDP should not be accessible from the public internet.",
            severity="high",
            resource_types=["azure_nsg"],
            condition=Condition(
                path="raw_data.AllowsRDPFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Remove NSG rules allowing RDP from 0.0.0.0/0 or *.",
            frameworks={"nist-800-53": ["SC-7", "CM-7"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-13/SC-28: Cryptographic Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-azure-sc-28-1",
            title="Azure Storage accounts should use encryption",
            description="Storage account encryption protects data at rest.",
            severity="high",
            resource_types=["azure_storage_account"],
            condition=Condition(
                path="raw_data.Encryption.Services.Blob.Enabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for Azure Storage accounts.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),
        CheckDefinition(
            id="nist-800-53-azure-sc-28-2",
            title="Azure SQL databases should have TDE enabled",
            description="Transparent Data Encryption protects SQL databases at rest.",
            severity="high",
            resource_types=["azure_sql_database"],
            condition=Condition(
                path="raw_data.TransparentDataEncryption.Status",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable TDE for Azure SQL databases.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),

        # ---------------------------------------------------------------------------
        # SI-4: System Monitoring
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-azure-si-4-1",
            title="Azure Security Center should be enabled",
            description="Security Center provides unified security management.",
            severity="high",
            resource_types=["azure_security_center"],
            condition=Condition(
                path="raw_data.Pricing.Tier",
                operator=Operator.EQUALS,
                value="Standard",
            ),
            remediation="Enable Azure Security Center Standard tier.",
            frameworks={"nist-800-53": ["SI-4", "SI-4(2)"]},
        ),
    ]


# =============================================================================
# GCP Compliance Checks
# =============================================================================


def get_nist_800_53_gcp_checks() -> list[CheckDefinition]:
    """
    Get GCP compliance checks mapped to NIST 800-53 controls.

    Returns:
        List of CheckDefinition objects for GCP resources.
    """
    return [
        # ---------------------------------------------------------------------------
        # AC-2: Account Management / IA-2: Identification and Authentication
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-gcp-ac-2-1",
            title="GCP users should have 2-step verification enabled",
            description="2-step verification protects against credential compromise.",
            severity="high",
            resource_types=["gcp_iam_user"],
            condition=Condition(
                path="raw_data.TwoStepVerificationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable 2-step verification for all GCP users.",
            frameworks={"nist-800-53": ["AC-2", "IA-2", "IA-2(1)"]},
        ),

        # ---------------------------------------------------------------------------
        # AU-2: Event Logging
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-gcp-au-2-1",
            title="Cloud Audit Logs should be enabled for all services",
            description="Audit logs provide visibility into GCP operations.",
            severity="high",
            resource_types=["gcp_project"],
            condition=Condition(
                path="raw_data.AuditLogConfig.AllServicesEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Cloud Audit Logs for all services in the project.",
            frameworks={"nist-800-53": ["AU-2", "AU-3", "AU-12"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-7: Boundary Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-gcp-sc-7-1",
            title="VPC firewall rules should not allow SSH from internet",
            description="SSH should not be accessible from the public internet.",
            severity="high",
            resource_types=["gcp_firewall_rule"],
            condition=Condition(
                path="raw_data.AllowsSSHFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict SSH access in firewall rules.",
            frameworks={"nist-800-53": ["SC-7", "CM-7"]},
        ),
        CheckDefinition(
            id="nist-800-53-gcp-sc-7-2",
            title="VPC firewall rules should not allow RDP from internet",
            description="RDP should not be accessible from the public internet.",
            severity="high",
            resource_types=["gcp_firewall_rule"],
            condition=Condition(
                path="raw_data.AllowsRDPFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict RDP access in firewall rules.",
            frameworks={"nist-800-53": ["SC-7", "CM-7"]},
        ),

        # ---------------------------------------------------------------------------
        # SC-13/SC-28: Cryptographic Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-gcp-sc-28-1",
            title="Cloud Storage buckets should have encryption enabled",
            description="Bucket encryption protects data at rest.",
            severity="high",
            resource_types=["gcp_storage_bucket"],
            condition=Condition(
                path="raw_data.Encryption",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable encryption for Cloud Storage buckets.",
            frameworks={"nist-800-53": ["SC-13", "SC-28"]},
        ),
        CheckDefinition(
            id="nist-800-53-gcp-sc-28-2",
            title="Cloud SQL instances should have encryption enabled",
            description="SQL encryption protects database data at rest.",
            severity="high",
            resource_types=["gcp_sql_instance"],
            condition=Condition(
                path="raw_data.Settings.IpConfiguration.RequireSsl",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for Cloud SQL instances.",
            frameworks={"nist-800-53": ["SC-13", "SC-28", "SC-8"]},
        ),

        # ---------------------------------------------------------------------------
        # SI-4: System Monitoring
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="nist-800-53-gcp-si-4-1",
            title="Cloud Security Command Center should be enabled",
            description="Security Command Center provides security monitoring.",
            severity="high",
            resource_types=["gcp_project"],
            condition=Condition(
                path="raw_data.SecurityCommandCenterEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Cloud Security Command Center.",
            frameworks={"nist-800-53": ["SI-4", "SI-4(2)"]},
        ),
    ]


# =============================================================================
# Framework Factory Functions
# =============================================================================


def create_nist_800_53_evaluator(baseline: str | None = None) -> Evaluator:
    """
    Create an evaluator pre-configured with NIST 800-53 checks.

    Args:
        baseline: Optional FedRAMP baseline to filter checks (low, moderate, high).

    Returns:
        Evaluator configured with NIST 800-53 checks.
    """
    evaluator = Evaluator()

    # Register all checks
    for check in get_nist_800_53_aws_checks():
        evaluator.register_check(check)

    for check in get_nist_800_53_azure_checks():
        evaluator.register_check(check)

    for check in get_nist_800_53_gcp_checks():
        evaluator.register_check(check)

    logger.info(
        f"Created NIST 800-53 evaluator with {len(evaluator.list_checks())} checks"
        f"{f' for {baseline} baseline' if baseline else ''}"
    )

    return evaluator


def get_nist_800_53_framework() -> NIST80053Framework:
    """
    Get the complete NIST 800-53 framework with controls and check mappings.

    Returns:
        NIST80053Framework instance with all controls and mappings.
    """
    framework = NIST80053Framework(
        version=NIST_800_53_VERSION,
        controls=NIST_800_53_CONTROLS,
    )

    # Build check mappings from all checks
    all_checks = (
        get_nist_800_53_aws_checks() +
        get_nist_800_53_azure_checks() +
        get_nist_800_53_gcp_checks()
    )

    for check in all_checks:
        if "nist-800-53" in check.frameworks:
            for control_id in check.frameworks["nist-800-53"]:
                if control_id not in framework.check_mappings:
                    framework.check_mappings[control_id] = []
                framework.check_mappings[control_id].append(check.id)

    logger.info(
        f"Built NIST 800-53 framework with {len(framework.controls)} controls, "
        f"{len(framework.check_mappings)} mapped to checks"
    )

    return framework
