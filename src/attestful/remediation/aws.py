"""
AWS-specific remediation actions for SOC 2 compliance.

Provides automated fixes for common AWS compliance issues including:
- S3 bucket encryption and versioning
- IAM password policy
- CloudTrail configuration
- Security group hardening
- RDS encryption and backups
"""

from __future__ import annotations

import asyncio
from typing import Any

from attestful.core.logging import get_logger
from attestful.remediation.base import (
    RemediationAction,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
)

logger = get_logger(__name__)


def _get_boto3_client(service: str, region: str = "us-east-1"):
    """Get boto3 client with lazy import."""
    import boto3

    return boto3.client(service, region_name=region)


# =============================================================================
# S3 Remediation Actions
# =============================================================================


class EnableS3BucketVersioningAction(RemediationAction):
    """Enable versioning on an S3 bucket (SOC 2 CC7.3, A1.2)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        region: str = "us-east-1",
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="s3_bucket",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.region = region
        self.bucket_name = resource_data.get("name") or resource_id

    async def validate(self) -> tuple[bool, str]:
        """Validate that versioning can be enabled."""
        try:
            from botocore.exceptions import ClientError

            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            # Check if bucket exists and is accessible
            await loop.run_in_executor(
                None,
                lambda: s3_client.head_bucket(Bucket=self.bucket_name),
            )

            return True, "Bucket is accessible and versioning can be enabled"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access bucket: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable versioning on the S3 bucket."""
        from botocore.exceptions import ClientError

        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable versioning on bucket {self.bucket_name}",
                    changes_made=["Enable S3 bucket versioning"],
                )

            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            # Get current versioning status for rollback
            current_versioning = await loop.run_in_executor(
                None,
                lambda: s3_client.get_bucket_versioning(Bucket=self.bucket_name),
            )

            self.rollback_data = {
                "bucket_name": self.bucket_name,
                "previous_status": current_versioning.get("Status", "Disabled"),
            }

            # Enable versioning
            await loop.run_in_executor(
                None,
                lambda: s3_client.put_bucket_versioning(
                    Bucket=self.bucket_name,
                    VersioningConfiguration={"Status": "Enabled"},
                ),
            )

            changes_made.append(f"Enabled versioning on bucket {self.bucket_name}")

            logger.info(
                "s3_versioning_enabled",
                extra={
                    "bucket": self.bucket_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled versioning on bucket {self.bucket_name}",
                changes_made=changes_made,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            logger.error(
                "s3_versioning_enable_failed",
                extra={
                    "bucket": self.bucket_name,
                    "error_code": error_code,
                },
            )

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable versioning: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback versioning changes (suspend versioning)."""
        if not self.rollback_data:
            return True

        try:
            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            previous_status = self.rollback_data.get("previous_status", "Disabled")

            if previous_status == "Disabled":
                # Note: Once enabled, versioning cannot be fully disabled, only suspended
                await loop.run_in_executor(
                    None,
                    lambda: s3_client.put_bucket_versioning(
                        Bucket=self.bucket_name,
                        VersioningConfiguration={"Status": "Suspended"},
                    ),
                )

            logger.info(
                "s3_versioning_rolled_back",
                extra={
                    "bucket": self.bucket_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "s3_versioning_rollback_failed",
                extra={
                    "bucket": self.bucket_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable versioning on S3 bucket '{self.bucket_name}' to protect against accidental deletion"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


class EnableS3BucketEncryptionAction(RemediationAction):
    """Enable default encryption on an S3 bucket (SOC 2 CC6.1)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        region: str = "us-east-1",
        kms_key_id: str | None = None,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="s3_bucket",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.region = region
        self.bucket_name = resource_data.get("name") or resource_id
        self.kms_key_id = kms_key_id

    async def validate(self) -> tuple[bool, str]:
        """Validate that encryption can be enabled."""
        try:
            from botocore.exceptions import ClientError

            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: s3_client.head_bucket(Bucket=self.bucket_name),
            )

            return True, "Bucket is accessible and encryption can be configured"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access bucket: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable default encryption on the S3 bucket."""
        from botocore.exceptions import ClientError

        changes_made = []

        try:
            if self.dry_run:
                enc_type = "KMS" if self.kms_key_id else "AES-256"
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable {enc_type} encryption on bucket {self.bucket_name}",
                    changes_made=[f"Enable {enc_type} default encryption"],
                )

            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            # Get current encryption for rollback
            try:
                current_encryption = await loop.run_in_executor(
                    None,
                    lambda: s3_client.get_bucket_encryption(Bucket=self.bucket_name),
                )
                self.rollback_data = {
                    "bucket_name": self.bucket_name,
                    "had_encryption": True,
                    "previous_config": current_encryption.get("ServerSideEncryptionConfiguration"),
                }
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "ServerSideEncryptionConfigurationNotFoundError":
                    self.rollback_data = {
                        "bucket_name": self.bucket_name,
                        "had_encryption": False,
                    }
                else:
                    raise

            # Configure encryption
            if self.kms_key_id:
                encryption_config = {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyID": self.kms_key_id,
                            },
                            "BucketKeyEnabled": True,
                        }
                    ]
                }
                enc_type = "KMS"
            else:
                encryption_config = {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            }
                        }
                    ]
                }
                enc_type = "AES-256"

            await loop.run_in_executor(
                None,
                lambda: s3_client.put_bucket_encryption(
                    Bucket=self.bucket_name,
                    ServerSideEncryptionConfiguration=encryption_config,
                ),
            )

            changes_made.append(f"Enabled {enc_type} encryption on bucket {self.bucket_name}")

            logger.info(
                "s3_encryption_enabled",
                extra={
                    "bucket": self.bucket_name,
                    "encryption_type": enc_type,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled {enc_type} encryption on bucket {self.bucket_name}",
                changes_made=changes_made,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable encryption: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback encryption changes."""
        if not self.rollback_data:
            return True

        try:
            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            if not self.rollback_data.get("had_encryption"):
                await loop.run_in_executor(
                    None,
                    lambda: s3_client.delete_bucket_encryption(Bucket=self.bucket_name),
                )
            elif self.rollback_data.get("previous_config"):
                await loop.run_in_executor(
                    None,
                    lambda: s3_client.put_bucket_encryption(
                        Bucket=self.bucket_name,
                        ServerSideEncryptionConfiguration=self.rollback_data["previous_config"],
                    ),
                )

            logger.info(
                "s3_encryption_rolled_back",
                extra={
                    "bucket": self.bucket_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "s3_encryption_rollback_failed",
                extra={
                    "bucket": self.bucket_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        enc_type = "KMS" if self.kms_key_id else "AES-256"
        return f"Enable {enc_type} default encryption on S3 bucket '{self.bucket_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


class BlockS3PublicAccessAction(RemediationAction):
    """Block public access on an S3 bucket (SOC 2 CC6.6)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        region: str = "us-east-1",
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="s3_bucket",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.region = region
        self.bucket_name = resource_data.get("name") or resource_id

    async def validate(self) -> tuple[bool, str]:
        """Validate that public access block can be configured."""
        try:
            from botocore.exceptions import ClientError

            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: s3_client.head_bucket(Bucket=self.bucket_name),
            )

            return True, "Bucket is accessible"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access bucket: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Block public access on the S3 bucket."""
        from botocore.exceptions import ClientError

        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would block public access on bucket {self.bucket_name}",
                    changes_made=["Block all public access"],
                )

            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            # Get current public access block for rollback
            try:
                current_block = await loop.run_in_executor(
                    None,
                    lambda: s3_client.get_public_access_block(Bucket=self.bucket_name),
                )
                self.rollback_data = {
                    "bucket_name": self.bucket_name,
                    "had_config": True,
                    "previous_config": current_block.get("PublicAccessBlockConfiguration"),
                }
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                    self.rollback_data = {
                        "bucket_name": self.bucket_name,
                        "had_config": False,
                    }
                else:
                    raise

            # Enable all public access blocks
            await loop.run_in_executor(
                None,
                lambda: s3_client.put_public_access_block(
                    Bucket=self.bucket_name,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                ),
            )

            changes_made.append(f"Blocked all public access on bucket {self.bucket_name}")

            logger.info(
                "s3_public_access_blocked",
                extra={
                    "bucket": self.bucket_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully blocked public access on bucket {self.bucket_name}",
                changes_made=changes_made,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to block public access: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback public access block changes."""
        if not self.rollback_data:
            return True

        try:
            s3_client = _get_boto3_client("s3", self.region)
            loop = asyncio.get_event_loop()

            if not self.rollback_data.get("had_config"):
                await loop.run_in_executor(
                    None,
                    lambda: s3_client.delete_public_access_block(Bucket=self.bucket_name),
                )
            elif self.rollback_data.get("previous_config"):
                await loop.run_in_executor(
                    None,
                    lambda: s3_client.put_public_access_block(
                        Bucket=self.bucket_name,
                        PublicAccessBlockConfiguration=self.rollback_data["previous_config"],
                    ),
                )

            logger.info(
                "s3_public_access_rolled_back",
                extra={
                    "bucket": self.bucket_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "s3_public_access_rollback_failed",
                extra={
                    "bucket": self.bucket_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Block all public access on S3 bucket '{self.bucket_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - medium because it may break public websites."""
        return RiskLevel.MEDIUM


# =============================================================================
# IAM Remediation Actions
# =============================================================================


class UpdateIAMPasswordPolicyAction(RemediationAction):
    """Update IAM password policy to meet compliance requirements (SOC 2 CC6.1)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        min_password_length: int = 14,
        require_symbols: bool = True,
        require_numbers: bool = True,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        max_password_age: int = 90,
        password_reuse_prevention: int = 24,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="iam_password_policy",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.min_password_length = min_password_length
        self.require_symbols = require_symbols
        self.require_numbers = require_numbers
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.max_password_age = max_password_age
        self.password_reuse_prevention = password_reuse_prevention

    async def validate(self) -> tuple[bool, str]:
        """Validate that password policy can be updated."""
        try:
            from botocore.exceptions import ClientError

            iam_client = _get_boto3_client("iam")
            loop = asyncio.get_event_loop()

            # Try to get current policy to verify access
            try:
                await loop.run_in_executor(
                    None,
                    iam_client.get_account_password_policy,
                )
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

            return True, "IAM access verified, password policy can be updated"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access IAM: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Update IAM password policy."""
        from botocore.exceptions import ClientError

        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message="[DRY RUN] Would update IAM password policy",
                    changes_made=[
                        f"Set minimum password length to {self.min_password_length}",
                        f"Set max password age to {self.max_password_age} days",
                        "Require uppercase, lowercase, numbers, and symbols",
                    ],
                )

            iam_client = _get_boto3_client("iam")
            loop = asyncio.get_event_loop()

            # Get current policy for rollback
            try:
                current_policy = await loop.run_in_executor(
                    None,
                    iam_client.get_account_password_policy,
                )
                self.rollback_data = {
                    "had_policy": True,
                    "previous_policy": current_policy.get("PasswordPolicy"),
                }
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                    self.rollback_data = {"had_policy": False}
                else:
                    raise

            # Update password policy
            await loop.run_in_executor(
                None,
                lambda: iam_client.update_account_password_policy(
                    MinimumPasswordLength=self.min_password_length,
                    RequireSymbols=self.require_symbols,
                    RequireNumbers=self.require_numbers,
                    RequireUppercaseCharacters=self.require_uppercase,
                    RequireLowercaseCharacters=self.require_lowercase,
                    MaxPasswordAge=self.max_password_age,
                    PasswordReusePrevention=self.password_reuse_prevention,
                    AllowUsersToChangePassword=True,
                ),
            )

            changes_made = [
                f"Set minimum password length to {self.min_password_length}",
                f"Set max password age to {self.max_password_age} days",
                f"Set password reuse prevention to {self.password_reuse_prevention}",
                f"RequireSymbols: {self.require_symbols}",
                f"RequireNumbers: {self.require_numbers}",
                f"RequireUppercase: {self.require_uppercase}",
                f"RequireLowercase: {self.require_lowercase}",
            ]

            logger.info(
                "iam_password_policy_updated",
                extra={"action_id": self.action_id},
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message="Successfully updated IAM password policy",
                changes_made=changes_made,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to update password policy: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback password policy changes."""
        if not self.rollback_data:
            return True

        try:
            iam_client = _get_boto3_client("iam")
            loop = asyncio.get_event_loop()

            if not self.rollback_data.get("had_policy"):
                await loop.run_in_executor(
                    None,
                    iam_client.delete_account_password_policy,
                )
            elif self.rollback_data.get("previous_policy"):
                policy = self.rollback_data["previous_policy"]
                await loop.run_in_executor(
                    None,
                    lambda: iam_client.update_account_password_policy(
                        MinimumPasswordLength=policy.get("MinimumPasswordLength", 8),
                        RequireSymbols=policy.get("RequireSymbols", False),
                        RequireNumbers=policy.get("RequireNumbers", False),
                        RequireUppercaseCharacters=policy.get("RequireUppercaseCharacters", False),
                        RequireLowercaseCharacters=policy.get("RequireLowercaseCharacters", False),
                        MaxPasswordAge=policy.get("MaxPasswordAge", 0),
                        PasswordReusePrevention=policy.get("PasswordReusePrevention", 0),
                        AllowUsersToChangePassword=policy.get("AllowUsersToChangePassword", True),
                    ),
                )

            logger.info("iam_password_policy_rolled_back", extra={"action_id": self.action_id})
            return True

        except Exception as e:
            logger.error("iam_password_policy_rollback_failed", extra={"error": str(e)})
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return (
            f"Update IAM password policy: min length {self.min_password_length}, "
            f"max age {self.max_password_age} days, require complexity"
        )

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - medium because it affects all IAM users."""
        return RiskLevel.MEDIUM


# =============================================================================
# CloudTrail Remediation Actions
# =============================================================================


class EnableCloudTrailLogValidationAction(RemediationAction):
    """Enable CloudTrail log file validation (SOC 2 CC7.2)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        trail_name: str,
        region: str = "us-east-1",
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="cloudtrail_trail",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.trail_name = trail_name
        self.region = region

    async def validate(self) -> tuple[bool, str]:
        """Validate that trail exists and can be updated."""
        try:
            from botocore.exceptions import ClientError

            ct_client = _get_boto3_client("cloudtrail", self.region)
            loop = asyncio.get_event_loop()

            trails = await loop.run_in_executor(
                None,
                lambda: ct_client.describe_trails(trailNameList=[self.trail_name]),
            )

            if not trails.get("trailList"):
                return False, f"Trail '{self.trail_name}' not found"

            return True, "Trail exists and can be updated"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access CloudTrail: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable log file validation on CloudTrail trail."""
        from botocore.exceptions import ClientError

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable log validation on trail {self.trail_name}",
                    changes_made=["Enable CloudTrail log file validation"],
                )

            ct_client = _get_boto3_client("cloudtrail", self.region)
            loop = asyncio.get_event_loop()

            # Get current trail config for rollback
            trails = await loop.run_in_executor(
                None,
                lambda: ct_client.describe_trails(trailNameList=[self.trail_name]),
            )

            trail = trails["trailList"][0]
            self.rollback_data = {
                "trail_name": self.trail_name,
                "previous_validation": trail.get("LogFileValidationEnabled", False),
            }

            # Enable log validation
            await loop.run_in_executor(
                None,
                lambda: ct_client.update_trail(
                    Name=self.trail_name,
                    EnableLogFileValidation=True,
                ),
            )

            logger.info(
                "cloudtrail_log_validation_enabled",
                extra={
                    "trail": self.trail_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled log validation on trail {self.trail_name}",
                changes_made=[f"Enabled log file validation on trail {self.trail_name}"],
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable log validation: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback log validation changes."""
        if not self.rollback_data:
            return True

        try:
            ct_client = _get_boto3_client("cloudtrail", self.region)
            loop = asyncio.get_event_loop()

            previous_validation = self.rollback_data.get("previous_validation", False)

            await loop.run_in_executor(
                None,
                lambda: ct_client.update_trail(
                    Name=self.trail_name,
                    EnableLogFileValidation=previous_validation,
                ),
            )

            logger.info("cloudtrail_log_validation_rolled_back", extra={"action_id": self.action_id})
            return True

        except Exception as e:
            logger.error("cloudtrail_log_validation_rollback_failed", extra={"error": str(e)})
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable log file validation on CloudTrail trail '{self.trail_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


# =============================================================================
# Security Group Remediation Actions
# =============================================================================


class RemoveOpenSSHAccessAction(RemediationAction):
    """Remove unrestricted SSH access (0.0.0.0/0:22) from security group (SOC 2 CC6.3)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        region: str = "us-east-1",
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="ec2_security_group",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.region = region
        self.group_id = resource_id

    async def validate(self) -> tuple[bool, str]:
        """Validate that security group can be modified."""
        try:
            from botocore.exceptions import ClientError

            ec2_client = _get_boto3_client("ec2", self.region)
            loop = asyncio.get_event_loop()

            result = await loop.run_in_executor(
                None,
                lambda: ec2_client.describe_security_groups(GroupIds=[self.group_id]),
            )

            if not result.get("SecurityGroups"):
                return False, f"Security group '{self.group_id}' not found"

            return True, "Security group exists and can be modified"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access security group: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Remove unrestricted SSH access from security group."""
        from botocore.exceptions import ClientError

        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would remove 0.0.0.0/0:22 from security group {self.group_id}",
                    changes_made=["Remove unrestricted SSH access (0.0.0.0/0:22)"],
                )

            ec2_client = _get_boto3_client("ec2", self.region)
            loop = asyncio.get_event_loop()

            # Get current rules for rollback
            result = await loop.run_in_executor(
                None,
                lambda: ec2_client.describe_security_groups(GroupIds=[self.group_id]),
            )

            sg = result["SecurityGroups"][0]
            self.rollback_data = {
                "group_id": self.group_id,
                "removed_rules": [],
            }

            # Find and remove SSH rules with 0.0.0.0/0
            for rule in sg.get("IpPermissions", []):
                if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            # Remove this rule
                            await loop.run_in_executor(
                                None,
                                lambda r=rule, ip=ip_range: ec2_client.revoke_security_group_ingress(
                                    GroupId=self.group_id,
                                    IpPermissions=[
                                        {
                                            "IpProtocol": r["IpProtocol"],
                                            "FromPort": 22,
                                            "ToPort": 22,
                                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                        }
                                    ],
                                ),
                            )

                            self.rollback_data["removed_rules"].append(
                                {
                                    "IpProtocol": rule["IpProtocol"],
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "CidrIp": "0.0.0.0/0",
                                }
                            )
                            changes_made.append(
                                f"Removed SSH access from 0.0.0.0/0 on security group {self.group_id}"
                            )

            if not changes_made:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message="No unrestricted SSH access found to remove",
                    changes_made=[],
                )

            logger.info(
                "security_group_ssh_removed",
                extra={
                    "group_id": self.group_id,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully removed unrestricted SSH access from {self.group_id}",
                changes_made=changes_made,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to remove SSH access: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback - re-add removed SSH rules."""
        if not self.rollback_data or not self.rollback_data.get("removed_rules"):
            return True

        try:
            ec2_client = _get_boto3_client("ec2", self.region)
            loop = asyncio.get_event_loop()

            for rule in self.rollback_data["removed_rules"]:
                await loop.run_in_executor(
                    None,
                    lambda r=rule: ec2_client.authorize_security_group_ingress(
                        GroupId=self.group_id,
                        IpPermissions=[
                            {
                                "IpProtocol": r["IpProtocol"],
                                "FromPort": r["FromPort"],
                                "ToPort": r["ToPort"],
                                "IpRanges": [{"CidrIp": r["CidrIp"]}],
                            }
                        ],
                    ),
                )

            logger.info("security_group_ssh_rolled_back", extra={"action_id": self.action_id})
            return True

        except Exception as e:
            logger.error("security_group_ssh_rollback_failed", extra={"error": str(e)})
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Remove unrestricted SSH access (0.0.0.0/0:22) from security group '{self.group_id}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - high because it may block legitimate access."""
        return RiskLevel.HIGH


# =============================================================================
# KMS Remediation Actions
# =============================================================================


class EnableKMSKeyRotationAction(RemediationAction):
    """Enable automatic key rotation on KMS key (SOC 2 CC6.1)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        region: str = "us-east-1",
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="kms_key",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.region = region
        self.key_id = resource_id

    async def validate(self) -> tuple[bool, str]:
        """Validate that key rotation can be enabled."""
        try:
            from botocore.exceptions import ClientError

            kms_client = _get_boto3_client("kms", self.region)
            loop = asyncio.get_event_loop()

            # Check if key exists and is customer managed
            key_info = await loop.run_in_executor(
                None,
                lambda: kms_client.describe_key(KeyId=self.key_id),
            )

            key_metadata = key_info.get("KeyMetadata", {})

            if key_metadata.get("KeyManager") != "CUSTOMER":
                return False, "Key rotation can only be enabled on customer-managed keys"

            if key_metadata.get("KeyState") != "Enabled":
                return False, f"Key is not enabled (state: {key_metadata.get('KeyState')})"

            if key_metadata.get("KeySpec") != "SYMMETRIC_DEFAULT":
                return False, "Key rotation is only available for symmetric keys"

            return True, "Key is eligible for rotation"

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            return False, f"Cannot access KMS key: {error_code}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable automatic key rotation."""
        from botocore.exceptions import ClientError

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable key rotation on {self.key_id}",
                    changes_made=["Enable automatic key rotation"],
                )

            kms_client = _get_boto3_client("kms", self.region)
            loop = asyncio.get_event_loop()

            # Get current rotation status for rollback
            rotation_status = await loop.run_in_executor(
                None,
                lambda: kms_client.get_key_rotation_status(KeyId=self.key_id),
            )

            self.rollback_data = {
                "key_id": self.key_id,
                "previous_rotation": rotation_status.get("KeyRotationEnabled", False),
            }

            # Enable key rotation
            await loop.run_in_executor(
                None,
                lambda: kms_client.enable_key_rotation(KeyId=self.key_id),
            )

            logger.info(
                "kms_key_rotation_enabled",
                extra={
                    "key_id": self.key_id,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled key rotation on {self.key_id}",
                changes_made=[f"Enabled automatic key rotation on KMS key {self.key_id}"],
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable key rotation: {error_code}",
                error=error_message,
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback - disable key rotation if it was previously disabled."""
        if not self.rollback_data:
            return True

        try:
            if self.rollback_data.get("previous_rotation"):
                # Rotation was already enabled, nothing to rollback
                return True

            kms_client = _get_boto3_client("kms", self.region)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: kms_client.disable_key_rotation(KeyId=self.key_id),
            )

            logger.info("kms_key_rotation_rolled_back", extra={"action_id": self.action_id})
            return True

        except Exception as e:
            logger.error("kms_key_rotation_rollback_failed", extra={"error": str(e)})
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable automatic key rotation on KMS key '{self.key_id}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


# =============================================================================
# Remediation Action Registry
# =============================================================================


# Map check IDs to remediation action classes
REMEDIATION_REGISTRY: dict[str, type[RemediationAction]] = {
    # S3 remediations
    "soc2-cc6.1-s3-encryption": EnableS3BucketEncryptionAction,
    "soc2-cc6.6-s3-public-access-blocked": BlockS3PublicAccessAction,
    "soc2-cc7.3-s3-versioning": EnableS3BucketVersioningAction,
    # IAM remediations
    "soc2-cc6.1-password-min-length": UpdateIAMPasswordPolicyAction,
    "soc2-cc6.1-password-uppercase": UpdateIAMPasswordPolicyAction,
    "soc2-cc6.1-password-lowercase": UpdateIAMPasswordPolicyAction,
    "soc2-cc6.1-password-numbers": UpdateIAMPasswordPolicyAction,
    "soc2-cc6.1-password-symbols": UpdateIAMPasswordPolicyAction,
    "soc2-cc6.1-password-expiration": UpdateIAMPasswordPolicyAction,
    # CloudTrail remediations
    "soc2-cc7.2-cloudtrail-log-validation": EnableCloudTrailLogValidationAction,
    # Security group remediations
    "soc2-cc6.3-no-public-ssh": RemoveOpenSSHAccessAction,
    # KMS remediations
    "soc2-cc6.1-kms-rotation": EnableKMSKeyRotationAction,
}


def get_remediation_action(
    check_id: str,
    resource_id: str,
    resource_data: dict[str, Any],
    region: str = "us-east-1",
    dry_run: bool = False,
    **kwargs: Any,
) -> RemediationAction | None:
    """
    Get a remediation action for a failed check.

    Args:
        check_id: ID of the failed compliance check
        resource_id: ID of the resource to remediate
        resource_data: Current resource data
        region: AWS region
        dry_run: If True, only simulate remediation
        **kwargs: Additional arguments for specific action types

    Returns:
        RemediationAction instance or None if no remediation available
    """
    action_class = REMEDIATION_REGISTRY.get(check_id)

    if not action_class:
        return None

    # Special handling for different action types
    if action_class == EnableCloudTrailLogValidationAction:
        trail_name = resource_data.get("TrailName") or kwargs.get("trail_name") or resource_id
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            trail_name=trail_name,
            region=region,
            dry_run=dry_run,
        )

    if action_class == EnableS3BucketEncryptionAction:
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            region=region,
            kms_key_id=kwargs.get("kms_key_id"),
            dry_run=dry_run,
        )

    if action_class == UpdateIAMPasswordPolicyAction:
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            dry_run=dry_run,
            **{k: v for k, v in kwargs.items() if k in [
                "min_password_length",
                "require_symbols",
                "require_numbers",
                "require_uppercase",
                "require_lowercase",
                "max_password_age",
                "password_reuse_prevention",
            ]},
        )

    # Default construction
    return action_class(
        check_id=check_id,
        resource_id=resource_id,
        resource_data=resource_data,
        region=region,
        dry_run=dry_run,
    )
