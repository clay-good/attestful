"""
AWS collector for Attestful.

Dual-mode collector supporting both resource collection (for compliance checks)
and evidence collection (for audit documentation).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from attestful.collectors.base import BaseCollector
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


@dataclass
class AWSCollectorConfig:
    """Configuration for AWS collector."""

    profile: str | None = None
    regions: list[str] = field(default_factory=list)
    assume_role_arn: str | None = None
    assume_role_session_name: str = "attestful-collector"
    assume_role_duration: int = 3600
    max_retries: int = 3
    timeout: int = 30


class AWSCollector(BaseCollector):
    """
    AWS collector for infrastructure resources and compliance evidence.

    Supports dual-mode operation:
    - Resource mode: Collects AWS resources for compliance checking
    - Evidence mode: Collects AWS configuration evidence for audits

    Resource Types:
    - ec2_instance: EC2 instances
    - ec2_security_group: Security groups
    - ec2_vpc: VPCs
    - s3_bucket: S3 buckets
    - iam_user: IAM users
    - iam_role: IAM roles
    - iam_policy: IAM policies
    - rds_instance: RDS instances
    - lambda_function: Lambda functions
    - cloudtrail_trail: CloudTrail trails
    - kms_key: KMS keys
    - sns_topic: SNS topics
    - sqs_queue: SQS queues

    Evidence Types:
    - account_info: AWS account information
    - iam_credential_report: IAM credential report
    - password_policy: Account password policy
    - cloudtrail_status: CloudTrail configuration status
    - config_recorder_status: AWS Config recorder status
    - guardduty_status: GuardDuty detector status
    - security_hub_status: Security Hub status
    - access_analyzer_status: IAM Access Analyzer status

    Example:
        collector = AWSCollector(
            config=AWSCollectorConfig(
                profile="production",
                regions=["us-east-1", "us-west-2"],
            )
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["ec2_instance", "s3_bucket"]
        )

        # Collect evidence for audits
        result = collector.collect_evidence(
            evidence_types=["iam_credential_report", "password_policy"]
        )
    """

    PLATFORM = "aws"
    SUPPORTED_RESOURCE_TYPES = [
        "ec2_instance",
        "ec2_security_group",
        "ec2_vpc",
        "s3_bucket",
        "iam_user",
        "iam_role",
        "iam_policy",
        "rds_instance",
        "lambda_function",
        "cloudtrail_trail",
        "kms_key",
        "sns_topic",
        "sqs_queue",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "account_info",
        "iam_credential_report",
        "password_policy",
        "cloudtrail_status",
        "config_recorder_status",
        "guardduty_status",
        "security_hub_status",
        "access_analyzer_status",
    ]

    def __init__(
        self,
        config: AWSCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize AWS collector.

        Args:
            config: AWS collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or AWSCollectorConfig()
        self._session: boto3.Session | None = None
        self._sts_credentials: dict[str, Any] | None = None
        self._account_id: str | None = None

    def _get_session(self) -> boto3.Session:
        """Get or create boto3 session."""
        if self._session is None:
            try:
                if self.config.profile:
                    self._session = boto3.Session(profile_name=self.config.profile)
                else:
                    self._session = boto3.Session()
            except ProfileNotFound as e:
                raise ConfigurationError(
                    f"AWS profile not found: {self.config.profile}",
                    cause=e,
                )
        return self._session

    def _get_client(self, service: str, region: str | None = None) -> Any:
        """
        Get boto3 client for a service.

        Args:
            service: AWS service name.
            region: AWS region (optional for global services).

        Returns:
            Boto3 client.
        """
        session = self._get_session()

        client_config = Config(
            retries={"max_attempts": self.config.max_retries, "mode": "adaptive"},
            connect_timeout=self.config.timeout,
            read_timeout=self.config.timeout,
        )

        kwargs: dict[str, Any] = {"config": client_config}
        if region:
            kwargs["region_name"] = region

        # Use assumed role credentials if configured
        if self.config.assume_role_arn:
            creds = self._get_assumed_role_credentials()
            kwargs.update({
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            })

        return session.client(service, **kwargs)

    def _get_assumed_role_credentials(self) -> dict[str, Any]:
        """Get credentials from assumed role."""
        if self._sts_credentials is None:
            session = self._get_session()
            sts = session.client("sts")

            response = sts.assume_role(
                RoleArn=self.config.assume_role_arn,
                RoleSessionName=self.config.assume_role_session_name,
                DurationSeconds=self.config.assume_role_duration,
            )
            self._sts_credentials = response["Credentials"]
            logger.info(f"Assumed role: {self.config.assume_role_arn}")

        return self._sts_credentials

    def _get_regions(self) -> list[str]:
        """Get regions to scan."""
        if self.config.regions:
            return self.config.regions

        # Get all enabled regions
        ec2 = self._get_client("ec2", region="us-east-1")
        response = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        return [r["RegionName"] for r in response["Regions"]]

    def _get_account_id(self) -> str:
        """Get AWS account ID."""
        if self._account_id is None:
            sts = self._get_client("sts")
            self._account_id = sts.get_caller_identity()["Account"]
        return self._account_id

    def validate_credentials(self) -> bool:
        """Validate AWS credentials."""
        try:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            logger.info(f"Validated AWS credentials for account {identity['Account']}")
            return True
        except (NoCredentialsError, ClientError) as e:
            logger.error(f"AWS credential validation failed: {e}")
            return False

    # =========================================================================
    # Resource Collection Methods
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """
        Collect AWS resources.

        Args:
            resource_types: List of resource types to collect.

        Returns:
            List of collected resources.
        """
        types_to_collect = resource_types or self.SUPPORTED_RESOURCE_TYPES
        resources: list[Resource] = []

        for resource_type in types_to_collect:
            if resource_type not in self.SUPPORTED_RESOURCE_TYPES:
                logger.warning(f"Unknown resource type: {resource_type}")
                continue

            collector_method = getattr(self, f"_collect_{resource_type}", None)
            if collector_method is None:
                logger.warning(f"No collector for resource type: {resource_type}")
                continue

            try:
                collected = list(collector_method())
                resources.extend(collected)
                logger.debug(f"Collected {len(collected)} {resource_type} resources")
            except Exception as e:
                logger.error(f"Failed to collect {resource_type}: {e}")

        return resources

    def _collect_ec2_instance(self) -> Iterator[Resource]:
        """Collect EC2 instances."""
        for region in self._get_regions():
            self._rate_limit()
            ec2 = self._get_client("ec2", region)

            try:
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for reservation in page["Reservations"]:
                        for instance in reservation["Instances"]:
                            yield Resource(
                                id=instance["InstanceId"],
                                type="ec2_instance",
                                provider="aws",
                                region=region,
                                name=self._get_tag_value(instance.get("Tags", []), "Name"),
                                raw_data=instance,
                            )
            except ClientError as e:
                logger.error(f"Failed to collect EC2 instances in {region}: {e}")

    def _collect_ec2_security_group(self) -> Iterator[Resource]:
        """Collect EC2 security groups."""
        for region in self._get_regions():
            self._rate_limit()
            ec2 = self._get_client("ec2", region)

            try:
                paginator = ec2.get_paginator("describe_security_groups")
                for page in paginator.paginate():
                    for sg in page["SecurityGroups"]:
                        yield Resource(
                            id=sg["GroupId"],
                            type="ec2_security_group",
                            provider="aws",
                            region=region,
                            name=sg.get("GroupName"),
                            raw_data=sg,
                        )
            except ClientError as e:
                logger.error(f"Failed to collect security groups in {region}: {e}")

    def _collect_ec2_vpc(self) -> Iterator[Resource]:
        """Collect VPCs."""
        for region in self._get_regions():
            self._rate_limit()
            ec2 = self._get_client("ec2", region)

            try:
                paginator = ec2.get_paginator("describe_vpcs")
                for page in paginator.paginate():
                    for vpc in page["Vpcs"]:
                        yield Resource(
                            id=vpc["VpcId"],
                            type="ec2_vpc",
                            provider="aws",
                            region=region,
                            name=self._get_tag_value(vpc.get("Tags", []), "Name"),
                            raw_data=vpc,
                        )
            except ClientError as e:
                logger.error(f"Failed to collect VPCs in {region}: {e}")

    def _collect_s3_bucket(self) -> Iterator[Resource]:
        """Collect S3 buckets."""
        self._rate_limit()
        s3 = self._get_client("s3")

        try:
            response = s3.list_buckets()
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]

                # Get bucket location
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get("LocationConstraint") or "us-east-1"
                except ClientError:
                    region = "unknown"

                # Get additional bucket details
                bucket_data = dict(bucket)
                try:
                    bucket_data["Versioning"] = s3.get_bucket_versioning(Bucket=bucket_name)
                except ClientError:
                    pass

                try:
                    bucket_data["Encryption"] = s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    bucket_data["Encryption"] = None

                try:
                    bucket_data["PublicAccessBlock"] = s3.get_public_access_block(Bucket=bucket_name)
                except ClientError:
                    bucket_data["PublicAccessBlock"] = None

                yield Resource(
                    id=bucket_name,
                    type="s3_bucket",
                    provider="aws",
                    region=region,
                    name=bucket_name,
                    raw_data=bucket_data,
                )
        except ClientError as e:
            logger.error(f"Failed to collect S3 buckets: {e}")

    def _collect_iam_user(self) -> Iterator[Resource]:
        """Collect IAM users."""
        self._rate_limit()
        iam = self._get_client("iam")

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    user_data = dict(user)

                    # Get user details
                    try:
                        mfa = iam.list_mfa_devices(UserName=user["UserName"])
                        user_data["MFADevices"] = mfa.get("MFADevices", [])
                    except ClientError:
                        pass

                    try:
                        keys = iam.list_access_keys(UserName=user["UserName"])
                        user_data["AccessKeys"] = keys.get("AccessKeyMetadata", [])
                    except ClientError:
                        pass

                    yield Resource(
                        id=user["UserId"],
                        type="iam_user",
                        provider="aws",
                        region="global",
                        name=user["UserName"],
                        raw_data=user_data,
                    )
        except ClientError as e:
            logger.error(f"Failed to collect IAM users: {e}")

    def _collect_iam_role(self) -> Iterator[Resource]:
        """Collect IAM roles."""
        self._rate_limit()
        iam = self._get_client("iam")

        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    yield Resource(
                        id=role["RoleId"],
                        type="iam_role",
                        provider="aws",
                        region="global",
                        name=role["RoleName"],
                        raw_data=role,
                    )
        except ClientError as e:
            logger.error(f"Failed to collect IAM roles: {e}")

    def _collect_iam_policy(self) -> Iterator[Resource]:
        """Collect IAM policies (customer managed only)."""
        self._rate_limit()
        iam = self._get_client("iam")

        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    yield Resource(
                        id=policy["PolicyId"],
                        type="iam_policy",
                        provider="aws",
                        region="global",
                        name=policy["PolicyName"],
                        raw_data=policy,
                    )
        except ClientError as e:
            logger.error(f"Failed to collect IAM policies: {e}")

    def _collect_rds_instance(self) -> Iterator[Resource]:
        """Collect RDS instances."""
        for region in self._get_regions():
            self._rate_limit()
            rds = self._get_client("rds", region)

            try:
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for instance in page["DBInstances"]:
                        yield Resource(
                            id=instance["DBInstanceIdentifier"],
                            type="rds_instance",
                            provider="aws",
                            region=region,
                            name=instance["DBInstanceIdentifier"],
                            raw_data=instance,
                        )
            except ClientError as e:
                logger.error(f"Failed to collect RDS instances in {region}: {e}")

    def _collect_lambda_function(self) -> Iterator[Resource]:
        """Collect Lambda functions."""
        for region in self._get_regions():
            self._rate_limit()
            lambda_client = self._get_client("lambda", region)

            try:
                paginator = lambda_client.get_paginator("list_functions")
                for page in paginator.paginate():
                    for func in page["Functions"]:
                        yield Resource(
                            id=func["FunctionArn"],
                            type="lambda_function",
                            provider="aws",
                            region=region,
                            name=func["FunctionName"],
                            raw_data=func,
                        )
            except ClientError as e:
                logger.error(f"Failed to collect Lambda functions in {region}: {e}")

    def _collect_cloudtrail_trail(self) -> Iterator[Resource]:
        """Collect CloudTrail trails."""
        self._rate_limit()
        cloudtrail = self._get_client("cloudtrail")

        try:
            response = cloudtrail.describe_trails()
            for trail in response.get("trailList", []):
                # Get trail status
                try:
                    status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
                    trail["Status"] = status
                except ClientError:
                    pass

                yield Resource(
                    id=trail["TrailARN"],
                    type="cloudtrail_trail",
                    provider="aws",
                    region=trail.get("HomeRegion", "global"),
                    name=trail["Name"],
                    raw_data=trail,
                )
        except ClientError as e:
            logger.error(f"Failed to collect CloudTrail trails: {e}")

    def _collect_kms_key(self) -> Iterator[Resource]:
        """Collect KMS keys."""
        for region in self._get_regions():
            self._rate_limit()
            kms = self._get_client("kms", region)

            try:
                paginator = kms.get_paginator("list_keys")
                for page in paginator.paginate():
                    for key_entry in page["Keys"]:
                        try:
                            key = kms.describe_key(KeyId=key_entry["KeyId"])["KeyMetadata"]
                            # Skip AWS managed keys
                            if key.get("KeyManager") == "AWS":
                                continue

                            yield Resource(
                                id=key["KeyId"],
                                type="kms_key",
                                provider="aws",
                                region=region,
                                name=key.get("Description") or key["KeyId"],
                                raw_data=key,
                            )
                        except ClientError:
                            pass
            except ClientError as e:
                logger.error(f"Failed to collect KMS keys in {region}: {e}")

    def _collect_sns_topic(self) -> Iterator[Resource]:
        """Collect SNS topics."""
        for region in self._get_regions():
            self._rate_limit()
            sns = self._get_client("sns", region)

            try:
                paginator = sns.get_paginator("list_topics")
                for page in paginator.paginate():
                    for topic in page["Topics"]:
                        arn = topic["TopicArn"]
                        name = arn.split(":")[-1]

                        try:
                            attrs = sns.get_topic_attributes(TopicArn=arn)
                            topic_data = attrs.get("Attributes", {})
                        except ClientError:
                            topic_data = {"TopicArn": arn}

                        yield Resource(
                            id=arn,
                            type="sns_topic",
                            provider="aws",
                            region=region,
                            name=name,
                            raw_data=topic_data,
                        )
            except ClientError as e:
                logger.error(f"Failed to collect SNS topics in {region}: {e}")

    def _collect_sqs_queue(self) -> Iterator[Resource]:
        """Collect SQS queues."""
        for region in self._get_regions():
            self._rate_limit()
            sqs = self._get_client("sqs", region)

            try:
                paginator = sqs.get_paginator("list_queues")
                for page in paginator.paginate():
                    for queue_url in page.get("QueueUrls", []):
                        name = queue_url.split("/")[-1]

                        try:
                            attrs = sqs.get_queue_attributes(
                                QueueUrl=queue_url,
                                AttributeNames=["All"],
                            )
                            queue_data = attrs.get("Attributes", {})
                            queue_data["QueueUrl"] = queue_url
                        except ClientError:
                            queue_data = {"QueueUrl": queue_url}

                        yield Resource(
                            id=queue_url,
                            type="sqs_queue",
                            provider="aws",
                            region=region,
                            name=name,
                            raw_data=queue_data,
                        )
            except ClientError as e:
                logger.error(f"Failed to collect SQS queues in {region}: {e}")

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect AWS evidence for compliance audits.

        Args:
            evidence_types: List of evidence types to collect.

        Returns:
            CollectionResult with collected evidence.
        """
        types_to_collect = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        for evidence_type in types_to_collect:
            if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:
                logger.warning(f"Unknown evidence type: {evidence_type}")
                continue

            collector_method = getattr(self, f"_evidence_{evidence_type}", None)
            if collector_method is None:
                logger.warning(f"No collector for evidence type: {evidence_type}")
                continue

            try:
                evidence = collector_method()
                if evidence:
                    evidence_items.append(evidence)
                    logger.debug(f"Collected {evidence_type} evidence")
            except Exception as e:
                error_msg = f"Failed to collect {evidence_type}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        return CollectionResult(
            platform=self.PLATFORM,
            evidence=evidence_items,
            errors=errors,
            collected_at=datetime.now(timezone.utc),
            metadata={
                "account_id": self._get_account_id(),
                "regions": self._get_regions(),
            },
        )

    def _evidence_account_info(self) -> Evidence:
        """Collect AWS account information."""
        self._rate_limit()
        sts = self._get_client("sts")
        identity = sts.get_caller_identity()

        # Try to get account alias
        iam = self._get_client("iam")
        try:
            aliases = iam.list_account_aliases()
            account_alias = aliases.get("AccountAliases", [None])[0]
        except ClientError:
            account_alias = None

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="account_info",
            raw_data={
                "account_id": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"],
                "account_alias": account_alias,
            },
            metadata={"source": "sts:GetCallerIdentity"},
        )

    def _evidence_iam_credential_report(self) -> Evidence:
        """Collect IAM credential report."""
        self._rate_limit()
        iam = self._get_client("iam")

        # Generate report
        try:
            iam.generate_credential_report()
        except ClientError:
            pass

        # Wait for report and retrieve
        import time
        for _ in range(10):
            try:
                response = iam.get_credential_report()
                content = response["Content"].decode("utf-8")
                break
            except ClientError as e:
                if "ReportNotPresent" in str(e) or "ReportInProgress" in str(e):
                    time.sleep(2)
                else:
                    raise
        else:
            raise CollectionError("Timeout waiting for credential report")

        # Parse CSV content
        import csv
        from io import StringIO

        reader = csv.DictReader(StringIO(content))
        users = list(reader)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="iam_credential_report",
            raw_data={
                "users": users,
                "generated_time": response.get("GeneratedTime", "").isoformat()
                if response.get("GeneratedTime")
                else None,
            },
            metadata={"source": "iam:GetCredentialReport"},
        )

    def _evidence_password_policy(self) -> Evidence:
        """Collect account password policy."""
        self._rate_limit()
        iam = self._get_client("iam")

        try:
            response = iam.get_account_password_policy()
            policy = response["PasswordPolicy"]
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                policy = {"exists": False, "message": "No password policy configured"}
            else:
                raise

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="password_policy",
            raw_data=policy,
            metadata={"source": "iam:GetAccountPasswordPolicy"},
        )

    def _evidence_cloudtrail_status(self) -> Evidence:
        """Collect CloudTrail configuration status."""
        self._rate_limit()
        cloudtrail = self._get_client("cloudtrail")

        trails = []
        response = cloudtrail.describe_trails()

        for trail in response.get("trailList", []):
            trail_info = dict(trail)
            try:
                status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
                trail_info["IsLogging"] = status.get("IsLogging", False)
                trail_info["LatestDeliveryTime"] = (
                    status.get("LatestDeliveryTime", "").isoformat()
                    if status.get("LatestDeliveryTime")
                    else None
                )
            except ClientError:
                trail_info["IsLogging"] = "unknown"

            trails.append(trail_info)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="cloudtrail_status",
            raw_data={"trails": trails},
            metadata={"source": "cloudtrail:DescribeTrails"},
        )

    def _evidence_config_recorder_status(self) -> Evidence:
        """Collect AWS Config recorder status."""
        recorders: list[dict[str, Any]] = []

        for region in self._get_regions():
            self._rate_limit()
            config = self._get_client("config", region)

            try:
                response = config.describe_configuration_recorders()
                for recorder in response.get("ConfigurationRecorders", []):
                    recorder_info = dict(recorder)
                    recorder_info["Region"] = region

                    # Get status
                    try:
                        status_response = config.describe_configuration_recorder_status(
                            ConfigurationRecorderNames=[recorder["name"]]
                        )
                        if status_response.get("ConfigurationRecordersStatus"):
                            recorder_info["Status"] = status_response["ConfigurationRecordersStatus"][0]
                    except ClientError:
                        pass

                    recorders.append(recorder_info)
            except ClientError as e:
                logger.warning(f"Failed to get Config status in {region}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="config_recorder_status",
            raw_data={"recorders": recorders},
            metadata={"source": "config:DescribeConfigurationRecorders"},
        )

    def _evidence_guardduty_status(self) -> Evidence:
        """Collect GuardDuty detector status."""
        detectors: list[dict[str, Any]] = []

        for region in self._get_regions():
            self._rate_limit()
            gd = self._get_client("guardduty", region)

            try:
                response = gd.list_detectors()
                for detector_id in response.get("DetectorIds", []):
                    try:
                        detector = gd.get_detector(DetectorId=detector_id)
                        detector["Region"] = region
                        detector["DetectorId"] = detector_id
                        detectors.append(detector)
                    except ClientError:
                        pass
            except ClientError as e:
                logger.warning(f"Failed to get GuardDuty status in {region}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="guardduty_status",
            raw_data={"detectors": detectors},
            metadata={"source": "guardduty:GetDetector"},
        )

    def _evidence_security_hub_status(self) -> Evidence:
        """Collect Security Hub status."""
        hubs: list[dict[str, Any]] = []

        for region in self._get_regions():
            self._rate_limit()
            sh = self._get_client("securityhub", region)

            try:
                hub = sh.describe_hub()
                hub["Region"] = region
                hubs.append(hub)
            except ClientError as e:
                if "not subscribed" not in str(e).lower():
                    logger.warning(f"Failed to get Security Hub status in {region}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_hub_status",
            raw_data={"hubs": hubs},
            metadata={"source": "securityhub:DescribeHub"},
        )

    def _evidence_access_analyzer_status(self) -> Evidence:
        """Collect IAM Access Analyzer status."""
        analyzers: list[dict[str, Any]] = []

        for region in self._get_regions():
            self._rate_limit()
            aa = self._get_client("accessanalyzer", region)

            try:
                response = aa.list_analyzers()
                for analyzer in response.get("analyzers", []):
                    analyzer["Region"] = region
                    analyzers.append(analyzer)
            except ClientError as e:
                logger.warning(f"Failed to get Access Analyzer status in {region}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="access_analyzer_status",
            raw_data={"analyzers": analyzers},
            metadata={"source": "accessanalyzer:ListAnalyzers"},
        )

    # =========================================================================
    # Utility Methods
    # =========================================================================

    @staticmethod
    def _get_tag_value(tags: list[dict[str, str]], key: str) -> str | None:
        """Get tag value by key from AWS tags list."""
        for tag in tags:
            if tag.get("Key") == key:
                return tag.get("Value")
        return None
