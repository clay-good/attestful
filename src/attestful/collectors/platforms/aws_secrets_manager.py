"""
AWS Secrets Manager collector.

Collects secrets management evidence from AWS Secrets Manager for
compliance verification and audit purposes.

Supports:
- Secret inventory and metadata collection
- Rotation configuration and compliance status
- Access logging via CloudTrail integration
- KMS key usage and encryption verification
- Resource policy analysis for access controls
- Secret version history and lifecycle tracking
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from attestful.collectors.base import (
    BaseCollector,
    CollectorMetadata,
    CollectorMode,
    register_collector,
)
from attestful.core.exceptions import (
    AuthenticationError,
    CollectionError,
    ConfigurationError,
)
from attestful.core.models import CollectionResult, Evidence


# Evidence types for AWS Secrets Manager
AWS_SECRETS_MANAGER_EVIDENCE_TYPES = [
    "secret_list",
    "secret_metadata",
    "rotation_config",
    "resource_policy",
    "version_history",
    "kms_key_usage",
    "access_logs",
    "replication_status",
    "secret_value_metadata",
    "compliance_status",
]


@dataclass
class SecretsManagerConfig:
    """AWS Secrets Manager collector configuration."""

    # AWS credentials
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_profile: str | None = None

    # Regions to collect from
    regions: list[str] | None = None

    # Collection options
    include_rotation_status: bool = True
    include_resource_policies: bool = True
    include_version_history: bool = True
    include_kms_details: bool = True
    include_access_logs: bool = True
    access_logs_days: int = 30

    # Secret age threshold for compliance alerts (days)
    rotation_age_threshold_days: int = 90


@register_collector()
class AWSSecretsManagerCollector(BaseCollector):
    """
    AWS Secrets Manager collector.

    Collects secrets management evidence including:
    - Secret inventory and metadata
    - Rotation configurations and status
    - Resource policies and access controls
    - Version history and lifecycle
    - KMS encryption key usage
    - CloudTrail access logs

    Evidence Types:
        - secret_list: List of all secrets with metadata
        - secret_metadata: Detailed metadata for each secret
        - rotation_config: Rotation configurations and lambda functions
        - resource_policy: IAM resource policies attached to secrets
        - version_history: Version staging labels and history
        - kms_key_usage: KMS keys used for encryption
        - access_logs: CloudTrail events for secret access
        - replication_status: Cross-region replication status
        - secret_value_metadata: Value metadata (not actual values)
        - compliance_status: Rotation and age compliance status

    Control Mappings:
        - NIST CSF: PR.AA, PR.DS
        - SOC 2: CC6.1, CC6.7
        - NIST 800-53: IA-5, SC-12, SC-28
        - ISO 27001: A.5.17, A.8.24
    """

    metadata = CollectorMetadata(
        name="AWS Secrets Manager",
        platform="aws_secrets_manager",
        description="AWS Secrets Manager secrets management collector",
        mode=CollectorMode.EVIDENCE,
        evidence_types=AWS_SECRETS_MANAGER_EVIDENCE_TYPES,
        requires_credentials=True,
        version="1.0.0",
    )

    def __init__(
        self,
        *,
        config: SecretsManagerConfig | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        aws_profile: str | None = None,
        regions: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize AWS Secrets Manager collector.

        Args:
            config: Pre-configured SecretsManagerConfig object
            aws_access_key_id: AWS access key ID
            aws_secret_access_key: AWS secret access key
            aws_session_token: AWS session token (for temporary credentials)
            aws_profile: AWS profile name from credentials file
            regions: List of regions to collect from (None = all enabled)
            **kwargs: Additional arguments for BaseCollector
        """
        super().__init__(**kwargs)

        if config:
            self.config = config
        else:
            self.config = SecretsManagerConfig(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                aws_profile=aws_profile,
                regions=regions,
            )

        self._clients: dict[str, Any] = {}
        self._session: Any = None

    def _get_session(self) -> Any:
        """Get or create boto3 session."""
        if self._session is None:
            try:
                import boto3
            except ImportError:
                raise ConfigurationError(
                    "boto3 is required for AWS Secrets Manager collection. "
                    "Install with: pip install boto3"
                )

            session_kwargs = {}
            if self.config.aws_profile:
                session_kwargs["profile_name"] = self.config.aws_profile
            if self.config.aws_access_key_id:
                session_kwargs["aws_access_key_id"] = self.config.aws_access_key_id
            if self.config.aws_secret_access_key:
                session_kwargs["aws_secret_access_key"] = (
                    self.config.aws_secret_access_key
                )
            if self.config.aws_session_token:
                session_kwargs["aws_session_token"] = self.config.aws_session_token

            self._session = boto3.Session(**session_kwargs)

        return self._session

    def _get_client(self, service: str, region: str) -> Any:
        """Get or create boto3 client for a service and region."""
        key = f"{service}:{region}"
        if key not in self._clients:
            session = self._get_session()
            self._clients[key] = session.client(service, region_name=region)
        return self._clients[key]

    def _get_enabled_regions(self) -> list[str]:
        """Get list of enabled regions."""
        if self.config.regions:
            return self.config.regions

        # Get all enabled regions
        session = self._get_session()
        ec2 = session.client("ec2", region_name="us-east-1")

        try:
            response = ec2.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            return [r["RegionName"] for r in response.get("Regions", [])]
        except Exception:
            # Fallback to common regions
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            ]

    def validate_credentials(self) -> bool:
        """Validate AWS credentials."""
        try:
            session = self._get_session()
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self.logger.info(
                f"Authenticated as {identity.get('Arn')} "
                f"(Account: {identity.get('Account')})"
            )
            return True
        except Exception as e:
            self.logger.error(f"AWS authentication failed: {e}")
            raise AuthenticationError(
                f"Failed to authenticate with AWS: {e}",
                provider="aws_secrets_manager",
            )

    # =========================================================================
    # Evidence Collection
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
        since: datetime | None = None,
        filters: dict[str, Any] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> CollectionResult:
        """
        Collect AWS Secrets Manager evidence.

        Args:
            evidence_types: Types of evidence to collect (None = all)
            since: Only collect evidence after this time
            filters: Additional filters (e.g., secret name patterns)
            progress_callback: Progress callback(current, total)

        Returns:
            CollectionResult with collected evidence
        """
        self.logger.info("Starting AWS Secrets Manager evidence collection")

        types_to_collect = evidence_types or AWS_SECRETS_MANAGER_EVIDENCE_TYPES
        regions = self._get_enabled_regions()
        total_steps = len(types_to_collect) * len(regions)
        current_step = 0

        all_evidence: list[Evidence] = []
        errors: list[str] = []

        for region in regions:
            self.logger.info(f"Collecting from region: {region}")

            for evidence_type in types_to_collect:
                if progress_callback:
                    progress_callback(current_step, total_steps)
                current_step += 1

                try:
                    evidence_items = self._collect_evidence_type(
                        evidence_type, region, since, filters
                    )
                    all_evidence.extend(evidence_items)
                    self.logger.debug(
                        f"Collected {len(evidence_items)} {evidence_type} items "
                        f"from {region}"
                    )
                except Exception as e:
                    error_msg = f"Failed to collect {evidence_type} from {region}: {e}"
                    self.logger.warning(error_msg)
                    errors.append(error_msg)

        if progress_callback:
            progress_callback(total_steps, total_steps)

        self.logger.info(
            f"Collected {len(all_evidence)} AWS Secrets Manager evidence items"
        )

        return CollectionResult(
            success=len(errors) == 0,
            evidence=all_evidence,
            errors=errors,
            metadata={
                "platform": "aws_secrets_manager",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "regions": regions,
                "evidence_types": types_to_collect,
            },
        )

    def _collect_evidence_type(
        self,
        evidence_type: str,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect evidence of a specific type from a region."""
        collectors = {
            "secret_list": self._collect_secret_list,
            "secret_metadata": self._collect_secret_metadata,
            "rotation_config": self._collect_rotation_config,
            "resource_policy": self._collect_resource_policies,
            "version_history": self._collect_version_history,
            "kms_key_usage": self._collect_kms_key_usage,
            "access_logs": self._collect_access_logs,
            "replication_status": self._collect_replication_status,
            "secret_value_metadata": self._collect_secret_value_metadata,
            "compliance_status": self._collect_compliance_status,
        }

        collector = collectors.get(evidence_type)
        if not collector:
            self.logger.warning(f"Unknown evidence type: {evidence_type}")
            return []

        return self._with_retry(
            lambda: collector(region, since, filters),
            f"collect_{evidence_type}",
        )

    def _list_secrets(self, region: str) -> list[dict]:
        """List all secrets in a region with pagination."""
        client = self._get_client("secretsmanager", region)
        secrets = []

        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))

        return secrets

    def _collect_secret_list(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect secret list evidence."""
        secrets = self._list_secrets(region)

        # Build summary
        summary = []
        for secret in secrets:
            summary.append({
                "name": secret.get("Name"),
                "arn": secret.get("ARN"),
                "rotation_enabled": secret.get("RotationEnabled", False),
                "last_rotated": (
                    secret.get("LastRotatedDate").isoformat()
                    if secret.get("LastRotatedDate")
                    else None
                ),
                "last_accessed": (
                    secret.get("LastAccessedDate").isoformat()
                    if secret.get("LastAccessedDate")
                    else None
                ),
                "created": (
                    secret.get("CreatedDate").isoformat()
                    if secret.get("CreatedDate")
                    else None
                ),
                "tags": {t["Key"]: t["Value"] for t in secret.get("Tags", [])},
            })

        return [
            self._create_evidence(
                evidence_type="secret_list",
                raw_data={"secrets": secrets},
                source_id=f"aws_secrets_manager_{region}",
                metadata={
                    "region": region,
                    "total_secrets": len(secrets),
                    "rotation_enabled_count": sum(
                        1 for s in secrets if s.get("RotationEnabled")
                    ),
                    "summary": summary,
                },
            )
        ]

    def _collect_secret_metadata(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed metadata for each secret."""
        client = self._get_client("secretsmanager", region)
        secrets = self._list_secrets(region)
        evidence_items = []

        for secret in secrets:
            secret_id = secret.get("ARN") or secret.get("Name")

            try:
                details = client.describe_secret(SecretId=secret_id)
            except Exception as e:
                self.logger.warning(f"Failed to describe secret {secret_id}: {e}")
                continue

            evidence_items.append(
                self._create_evidence(
                    evidence_type="secret_metadata",
                    raw_data=details,
                    source_id=secret.get("Name"),
                    metadata={
                        "region": region,
                        "name": details.get("Name"),
                        "arn": details.get("ARN"),
                        "kms_key_id": details.get("KmsKeyId"),
                        "rotation_enabled": details.get("RotationEnabled", False),
                        "rotation_lambda_arn": details.get("RotationLambdaARN"),
                        "rotation_rules": details.get("RotationRules"),
                        "last_rotated": (
                            details.get("LastRotatedDate").isoformat()
                            if details.get("LastRotatedDate")
                            else None
                        ),
                        "last_changed": (
                            details.get("LastChangedDate").isoformat()
                            if details.get("LastChangedDate")
                            else None
                        ),
                        "last_accessed": (
                            details.get("LastAccessedDate").isoformat()
                            if details.get("LastAccessedDate")
                            else None
                        ),
                        "deletion_date": (
                            details.get("DeletedDate").isoformat()
                            if details.get("DeletedDate")
                            else None
                        ),
                        "owning_service": details.get("OwningService"),
                        "primary_region": details.get("PrimaryRegion"),
                        "replication_status": details.get("ReplicationStatus"),
                        "tags": {
                            t["Key"]: t["Value"] for t in details.get("Tags", [])
                        },
                    },
                )
            )

        return evidence_items

    def _collect_rotation_config(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect rotation configuration evidence."""
        client = self._get_client("secretsmanager", region)
        secrets = self._list_secrets(region)
        evidence_items = []

        for secret in secrets:
            secret_id = secret.get("ARN") or secret.get("Name")

            try:
                details = client.describe_secret(SecretId=secret_id)
            except Exception as e:
                self.logger.warning(f"Failed to get rotation config for {secret_id}: {e}")
                continue

            rotation_enabled = details.get("RotationEnabled", False)
            rotation_rules = details.get("RotationRules", {})
            last_rotated = details.get("LastRotatedDate")

            # Calculate days since last rotation
            days_since_rotation = None
            if last_rotated:
                delta = datetime.now(timezone.utc) - last_rotated.replace(
                    tzinfo=timezone.utc
                )
                days_since_rotation = delta.days

            # Check compliance
            rotation_compliant = True
            compliance_issues = []

            if not rotation_enabled:
                compliance_issues.append("Rotation is not enabled")
                rotation_compliant = False
            elif days_since_rotation is not None:
                threshold = self.config.rotation_age_threshold_days
                if days_since_rotation > threshold:
                    compliance_issues.append(
                        f"Secret not rotated in {days_since_rotation} days "
                        f"(threshold: {threshold})"
                    )
                    rotation_compliant = False

            evidence_items.append(
                self._create_evidence(
                    evidence_type="rotation_config",
                    raw_data={
                        "secret_name": secret.get("Name"),
                        "secret_arn": secret.get("ARN"),
                        "rotation_enabled": rotation_enabled,
                        "rotation_lambda_arn": details.get("RotationLambdaARN"),
                        "rotation_rules": rotation_rules,
                        "last_rotated": (
                            last_rotated.isoformat() if last_rotated else None
                        ),
                        "days_since_rotation": days_since_rotation,
                    },
                    source_id=secret.get("Name"),
                    metadata={
                        "region": region,
                        "rotation_enabled": rotation_enabled,
                        "rotation_interval_days": rotation_rules.get(
                            "AutomaticallyAfterDays"
                        ),
                        "schedule_expression": rotation_rules.get(
                            "ScheduleExpression"
                        ),
                        "days_since_rotation": days_since_rotation,
                        "rotation_compliant": rotation_compliant,
                        "compliance_issues": compliance_issues,
                    },
                )
            )

        return evidence_items

    def _collect_resource_policies(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect resource policy evidence."""
        client = self._get_client("secretsmanager", region)
        secrets = self._list_secrets(region)
        evidence_items = []

        for secret in secrets:
            secret_id = secret.get("ARN") or secret.get("Name")

            try:
                response = client.get_resource_policy(SecretId=secret_id)
                policy = response.get("ResourcePolicy")
                if policy:
                    policy = json.loads(policy)
            except client.exceptions.ResourceNotFoundException:
                policy = None
            except Exception as e:
                self.logger.warning(f"Failed to get policy for {secret_id}: {e}")
                continue

            evidence_items.append(
                self._create_evidence(
                    evidence_type="resource_policy",
                    raw_data={
                        "secret_name": secret.get("Name"),
                        "secret_arn": secret.get("ARN"),
                        "policy": policy,
                    },
                    source_id=secret.get("Name"),
                    metadata={
                        "region": region,
                        "has_policy": policy is not None,
                        "statement_count": (
                            len(policy.get("Statement", []))
                            if policy
                            else 0
                        ),
                        "principals": (
                            self._extract_principals(policy) if policy else []
                        ),
                    },
                )
            )

        return evidence_items

    def _extract_principals(self, policy: dict) -> list[str]:
        """Extract unique principals from a policy."""
        principals = set()
        for statement in policy.get("Statement", []):
            principal = statement.get("Principal", {})
            if isinstance(principal, str):
                principals.add(principal)
            elif isinstance(principal, dict):
                for key, values in principal.items():
                    if isinstance(values, str):
                        principals.add(values)
                    elif isinstance(values, list):
                        principals.update(values)
        return list(principals)

    def _collect_version_history(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect version history evidence."""
        client = self._get_client("secretsmanager", region)
        secrets = self._list_secrets(region)
        evidence_items = []

        for secret in secrets:
            secret_id = secret.get("ARN") or secret.get("Name")

            try:
                versions = []
                paginator = client.get_paginator("list_secret_version_ids")
                for page in paginator.paginate(SecretId=secret_id):
                    versions.extend(page.get("Versions", []))
            except Exception as e:
                self.logger.warning(f"Failed to get versions for {secret_id}: {e}")
                continue

            # Process versions
            version_summary = []
            for version in versions:
                version_summary.append({
                    "version_id": version.get("VersionId"),
                    "version_stages": version.get("VersionStages", []),
                    "created_date": (
                        version.get("CreatedDate").isoformat()
                        if version.get("CreatedDate")
                        else None
                    ),
                    "last_accessed_date": (
                        version.get("LastAccessedDate").isoformat()
                        if version.get("LastAccessedDate")
                        else None
                    ),
                })

            evidence_items.append(
                self._create_evidence(
                    evidence_type="version_history",
                    raw_data={
                        "secret_name": secret.get("Name"),
                        "secret_arn": secret.get("ARN"),
                        "versions": versions,
                    },
                    source_id=secret.get("Name"),
                    metadata={
                        "region": region,
                        "version_count": len(versions),
                        "current_version": next(
                            (
                                v.get("VersionId")
                                for v in versions
                                if "AWSCURRENT" in v.get("VersionStages", [])
                            ),
                            None,
                        ),
                        "has_previous": any(
                            "AWSPREVIOUS" in v.get("VersionStages", [])
                            for v in versions
                        ),
                        "summary": version_summary,
                    },
                )
            )

        return evidence_items

    def _collect_kms_key_usage(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect KMS key usage evidence."""
        secrets = self._list_secrets(region)

        # Group secrets by KMS key
        kms_keys: dict[str, list[str]] = {}
        for secret in secrets:
            kms_key = secret.get("KmsKeyId", "aws/secretsmanager")
            if kms_key not in kms_keys:
                kms_keys[kms_key] = []
            kms_keys[kms_key].append(secret.get("Name"))

        # Get KMS key details
        kms_client = self._get_client("kms", region)
        key_details = []

        for key_id, secret_names in kms_keys.items():
            try:
                if key_id == "aws/secretsmanager" or key_id.startswith("alias/"):
                    # Default key or alias
                    key_info = {"KeyId": key_id, "managed": True}
                else:
                    key_info = kms_client.describe_key(KeyId=key_id).get(
                        "KeyMetadata", {}
                    )
            except Exception:
                key_info = {"KeyId": key_id, "error": "Unable to describe key"}

            key_details.append({
                "key_id": key_id,
                "key_info": key_info,
                "secrets_using_key": secret_names,
                "secret_count": len(secret_names),
            })

        return [
            self._create_evidence(
                evidence_type="kms_key_usage",
                raw_data={"kms_keys": key_details},
                source_id=f"aws_secrets_manager_kms_{region}",
                metadata={
                    "region": region,
                    "unique_keys": len(kms_keys),
                    "using_default_key": "aws/secretsmanager" in kms_keys,
                    "using_cmk": any(
                        not (k == "aws/secretsmanager" or k.startswith("alias/"))
                        for k in kms_keys.keys()
                    ),
                },
            )
        ]

    def _collect_access_logs(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect secret access logs from CloudTrail."""
        if not self.config.include_access_logs:
            return []

        cloudtrail = self._get_client("cloudtrail", region)

        # Determine time range
        end_time = datetime.now(timezone.utc)
        start_time = since or (
            end_time - timedelta(days=self.config.access_logs_days)
        )

        try:
            events = []
            paginator = cloudtrail.get_paginator("lookup_events")

            for page in paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "EventSource", "AttributeValue": "secretsmanager.amazonaws.com"}
                ],
                StartTime=start_time,
                EndTime=end_time,
            ):
                events.extend(page.get("Events", []))

        except Exception as e:
            self.logger.warning(f"Failed to get CloudTrail events: {e}")
            return []

        # Summarize events
        event_summary = {}
        for event in events:
            event_name = event.get("EventName")
            if event_name not in event_summary:
                event_summary[event_name] = 0
            event_summary[event_name] += 1

        return [
            self._create_evidence(
                evidence_type="access_logs",
                raw_data={"events": events},
                source_id=f"aws_secrets_manager_access_{region}",
                metadata={
                    "region": region,
                    "total_events": len(events),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "event_summary": event_summary,
                    "get_secret_value_count": event_summary.get(
                        "GetSecretValue", 0
                    ),
                },
            )
        ]

    def _collect_replication_status(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect cross-region replication status."""
        secrets = self._list_secrets(region)
        evidence_items = []

        for secret in secrets:
            replication_status = secret.get("ReplicationStatus", [])

            if replication_status:
                evidence_items.append(
                    self._create_evidence(
                        evidence_type="replication_status",
                        raw_data={
                            "secret_name": secret.get("Name"),
                            "secret_arn": secret.get("ARN"),
                            "primary_region": secret.get("PrimaryRegion"),
                            "replication_status": replication_status,
                        },
                        source_id=secret.get("Name"),
                        metadata={
                            "region": region,
                            "is_primary": secret.get("PrimaryRegion") == region,
                            "replica_count": len(replication_status),
                            "replica_regions": [
                                r.get("Region") for r in replication_status
                            ],
                            "all_synced": all(
                                r.get("Status") == "InSync"
                                for r in replication_status
                            ),
                        },
                    )
                )

        return evidence_items

    def _collect_secret_value_metadata(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect secret value metadata (NOT actual values)."""
        client = self._get_client("secretsmanager", region)
        secrets = self._list_secrets(region)
        evidence_items = []

        for secret in secrets:
            secret_id = secret.get("ARN") or secret.get("Name")

            try:
                # Get secret value to determine type (string vs binary)
                # We only look at metadata, NOT the actual value
                response = client.get_secret_value(SecretId=secret_id)

                # Determine type and compute hash (for change detection)
                if "SecretString" in response:
                    value_type = "string"
                    value_hash = hashlib.sha256(
                        response["SecretString"].encode()
                    ).hexdigest()[:16]
                elif "SecretBinary" in response:
                    value_type = "binary"
                    value_hash = hashlib.sha256(
                        response["SecretBinary"]
                    ).hexdigest()[:16]
                else:
                    value_type = "unknown"
                    value_hash = None

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="secret_value_metadata",
                        raw_data={
                            "secret_name": secret.get("Name"),
                            "secret_arn": secret.get("ARN"),
                            "version_id": response.get("VersionId"),
                            "version_stages": response.get("VersionStages", []),
                            "created_date": (
                                response.get("CreatedDate").isoformat()
                                if response.get("CreatedDate")
                                else None
                            ),
                            "value_type": value_type,
                            "value_hash_prefix": value_hash,
                        },
                        source_id=secret.get("Name"),
                        metadata={
                            "region": region,
                            "value_type": value_type,
                            "version_id": response.get("VersionId"),
                            "is_current": "AWSCURRENT" in response.get(
                                "VersionStages", []
                            ),
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(
                    f"Failed to get value metadata for {secret_id}: {e}"
                )

        return evidence_items

    def _collect_compliance_status(
        self,
        region: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect overall compliance status."""
        client = self._get_client("secretsmanager", region)
        secrets = self._list_secrets(region)

        compliant_secrets = []
        non_compliant_secrets = []
        compliance_issues_by_secret = {}

        for secret in secrets:
            secret_name = secret.get("Name")
            issues = []

            # Check rotation
            if not secret.get("RotationEnabled"):
                issues.append("Rotation not enabled")

            # Check rotation age
            last_rotated = secret.get("LastRotatedDate")
            if last_rotated:
                delta = datetime.now(timezone.utc) - last_rotated.replace(
                    tzinfo=timezone.utc
                )
                if delta.days > self.config.rotation_age_threshold_days:
                    issues.append(
                        f"Not rotated in {delta.days} days"
                    )
            elif secret.get("RotationEnabled"):
                issues.append("Never rotated")

            # Check encryption
            kms_key = secret.get("KmsKeyId")
            if kms_key == "aws/secretsmanager" or not kms_key:
                issues.append("Using default AWS managed key")

            # Check tags
            tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}
            if "Owner" not in tags and "owner" not in tags:
                issues.append("Missing Owner tag")

            if issues:
                non_compliant_secrets.append(secret_name)
                compliance_issues_by_secret[secret_name] = issues
            else:
                compliant_secrets.append(secret_name)

        compliance_score = (
            len(compliant_secrets) / len(secrets) * 100 if secrets else 100
        )

        return [
            self._create_evidence(
                evidence_type="compliance_status",
                raw_data={
                    "compliant_secrets": compliant_secrets,
                    "non_compliant_secrets": non_compliant_secrets,
                    "issues_by_secret": compliance_issues_by_secret,
                },
                source_id=f"aws_secrets_manager_compliance_{region}",
                metadata={
                    "region": region,
                    "total_secrets": len(secrets),
                    "compliant_count": len(compliant_secrets),
                    "non_compliant_count": len(non_compliant_secrets),
                    "compliance_score": round(compliance_score, 2),
                    "rotation_threshold_days": self.config.rotation_age_threshold_days,
                },
            )
        ]
