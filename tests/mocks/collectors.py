"""
Mock collectors for offline testing.

Provides mock implementations of collectors that use recorded API
responses, enabling deterministic testing without network access.

Usage:
    # Use recorded responses
    collector = MockAWSCollector(responses_dir="tests/recorded_responses/aws")
    result = collector.collect_resources()

    # Use fixture data
    collector = MockAWSCollector.with_fixtures(fixtures={"buckets": [...]})
    result = collector.collect_resources()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from attestful.core.models import Resource, Evidence, CollectionResult


# =============================================================================
# Response Recording and Playback
# =============================================================================


@dataclass
class RecordedResponse:
    """A recorded API response for replay."""

    endpoint: str
    method: str
    status_code: int
    response_data: dict[str, Any] | list[Any]
    recorded_at: str
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "status_code": self.status_code,
            "response_data": self.response_data,
            "recorded_at": self.recorded_at,
            "headers": self.headers,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecordedResponse:
        """Create from dictionary."""
        return cls(
            endpoint=data["endpoint"],
            method=data["method"],
            status_code=data["status_code"],
            response_data=data["response_data"],
            recorded_at=data["recorded_at"],
            headers=data.get("headers", {}),
            metadata=data.get("metadata", {}),
        )


def load_recorded_response(path: Path) -> RecordedResponse:
    """Load a recorded response from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    return RecordedResponse.from_dict(data)


def save_recorded_response(response: RecordedResponse, path: Path) -> None:
    """Save a recorded response to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(response.to_dict(), f, indent=2)


class ResponsePlayer:
    """Plays back recorded API responses."""

    def __init__(self, responses_dir: Path | None = None) -> None:
        """
        Initialize response player.

        Args:
            responses_dir: Directory containing recorded responses.
        """
        self.responses_dir = responses_dir
        self._responses: dict[str, RecordedResponse] = {}
        self._loaded = False

    def _load_responses(self) -> None:
        """Load all responses from directory."""
        if self._loaded or not self.responses_dir:
            return

        if self.responses_dir.exists():
            for response_file in self.responses_dir.glob("*.json"):
                response = load_recorded_response(response_file)
                key = f"{response.method}:{response.endpoint}"
                self._responses[key] = response

        self._loaded = True

    def get_response(self, endpoint: str, method: str = "GET") -> RecordedResponse | None:
        """Get a recorded response for an endpoint."""
        self._load_responses()
        key = f"{method}:{endpoint}"
        return self._responses.get(key)

    def add_response(self, response: RecordedResponse) -> None:
        """Add a response to the player."""
        key = f"{response.method}:{response.endpoint}"
        self._responses[key] = response


# =============================================================================
# Base Mock Collector
# =============================================================================


class MockCollectorBase:
    """Base class for mock collectors."""

    PROVIDER: str = "mock"
    PLATFORM: str = "mock"

    def __init__(
        self,
        responses_dir: Path | None = None,
        fixtures: dict[str, Any] | None = None,
        fail_after: int | None = None,
        delay_ms: int = 0,
    ) -> None:
        """
        Initialize mock collector.

        Args:
            responses_dir: Directory with recorded responses.
            fixtures: Fixture data to use instead of recorded responses.
            fail_after: Fail after this many calls (for error testing).
            delay_ms: Simulated delay in milliseconds.
        """
        self.responses_dir = responses_dir
        self.fixtures = fixtures or {}
        self.fail_after = fail_after
        self.delay_ms = delay_ms
        self._call_count = 0
        self._player = ResponsePlayer(responses_dir)

    @classmethod
    def with_fixtures(cls, fixtures: dict[str, Any], **kwargs: Any) -> "MockCollectorBase":
        """Create a mock collector with fixture data."""
        return cls(fixtures=fixtures, **kwargs)

    def _should_fail(self) -> bool:
        """Check if this call should fail."""
        self._call_count += 1
        if self.fail_after is not None and self._call_count > self.fail_after:
            return True
        return False

    def _get_fixture_or_response(
        self,
        fixture_key: str,
        endpoint: str,
        default: Any = None,
    ) -> Any:
        """Get data from fixtures or recorded responses."""
        # Check fixtures first
        if fixture_key in self.fixtures:
            return self.fixtures[fixture_key]

        # Check recorded responses
        response = self._player.get_response(endpoint)
        if response:
            return response.response_data

        return default


# =============================================================================
# AWS Mock Collector
# =============================================================================


class MockAWSCollector(MockCollectorBase):
    """Mock AWS collector for testing."""

    PROVIDER = "aws"
    PLATFORM = "aws"

    DEFAULT_FIXTURES = {
        "buckets": [
            {
                "Name": "test-bucket-1",
                "CreationDate": "2024-01-01T00:00:00Z",
                "Encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                },
                "Versioning": {"Status": "Enabled"},
                "PublicAccessBlock": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
            },
            {
                "Name": "test-bucket-2",
                "CreationDate": "2024-02-01T00:00:00Z",
                "Encryption": None,
                "Versioning": {"Status": "Suspended"},
                "PublicAccessBlock": None,
            },
        ],
        "instances": [
            {
                "InstanceId": "i-1234567890abcdef0",
                "InstanceType": "t3.medium",
                "State": {"Name": "running"},
                "MetadataOptions": {"HttpTokens": "required"},
            },
        ],
        "users": [
            {
                "UserName": "admin",
                "UserId": "AIDAEXAMPLE",
                "Arn": "arn:aws:iam::123456789012:user/admin",
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/admin"}],
            },
            {
                "UserName": "developer",
                "UserId": "AIDAEXAMPLE2",
                "Arn": "arn:aws:iam::123456789012:user/developer",
                "MFADevices": [],
            },
        ],
    }

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
        regions: list[str] | None = None,
    ) -> list[Resource]:
        """Collect mock AWS resources."""
        if self._should_fail():
            raise RuntimeError("Mock failure triggered")

        resources = []

        # Get fixtures with defaults
        fixtures = {**self.DEFAULT_FIXTURES, **self.fixtures}

        # S3 Buckets
        if not resource_types or "s3_bucket" in resource_types:
            for bucket in fixtures.get("buckets", []):
                resources.append(
                    Resource(
                        id=f"arn:aws:s3:::{bucket['Name']}",
                        type="s3_bucket",
                        provider="aws",
                        region="global",
                        name=bucket["Name"],
                        raw_data=bucket,
                    )
                )

        # EC2 Instances
        if not resource_types or "ec2_instance" in resource_types:
            for instance in fixtures.get("instances", []):
                resources.append(
                    Resource(
                        id=instance["InstanceId"],
                        type="ec2_instance",
                        provider="aws",
                        region=regions[0] if regions else "us-east-1",
                        name=instance.get("Tags", {}).get("Name", instance["InstanceId"]),
                        raw_data=instance,
                    )
                )

        # IAM Users
        if not resource_types or "iam_user" in resource_types:
            for user in fixtures.get("users", []):
                resources.append(
                    Resource(
                        id=user["Arn"],
                        type="iam_user",
                        provider="aws",
                        name=user["UserName"],
                        raw_data=user,
                    )
                )

        return resources

    def collect_evidence(self) -> CollectionResult:
        """Collect mock AWS evidence."""
        if self._should_fail():
            result = CollectionResult(success=False, platform="aws")
            result.add_error("Mock failure triggered")
            return result

        result = CollectionResult(success=True, platform="aws")

        # Add IAM credential report evidence
        result.add_evidence(
            Evidence(
                id="evidence-aws-iam-001",
                platform="aws",
                evidence_type="iam_credential_report",
                collected_at=datetime.now(timezone.utc),
                raw_data={
                    "users": self.fixtures.get("users", self.DEFAULT_FIXTURES["users"]),
                },
                metadata={"source": "mock"},
            )
        )

        result.complete()
        return result


# =============================================================================
# Azure Mock Collector
# =============================================================================


class MockAzureCollector(MockCollectorBase):
    """Mock Azure collector for testing."""

    PROVIDER = "azure"
    PLATFORM = "azure"

    DEFAULT_FIXTURES = {
        "storage_accounts": [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/storage1",
                "name": "storage1",
                "type": "Microsoft.Storage/storageAccounts",
                "location": "eastus",
                "properties": {
                    "encryption": {"services": {"blob": {"enabled": True}}},
                    "allowBlobPublicAccess": False,
                },
            },
        ],
        "virtual_machines": [
            {
                "id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm1",
                "name": "vm1",
                "type": "Microsoft.Compute/virtualMachines",
                "location": "eastus",
                "properties": {
                    "osProfile": {"computerName": "vm1"},
                    "hardwareProfile": {"vmSize": "Standard_D2s_v3"},
                },
            },
        ],
    }

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
        subscriptions: list[str] | None = None,
    ) -> list[Resource]:
        """Collect mock Azure resources."""
        if self._should_fail():
            raise RuntimeError("Mock failure triggered")

        resources = []
        fixtures = {**self.DEFAULT_FIXTURES, **self.fixtures}

        # Storage Accounts
        if not resource_types or "storage_account" in resource_types:
            for account in fixtures.get("storage_accounts", []):
                resources.append(
                    Resource(
                        id=account["id"],
                        type="storage_account",
                        provider="azure",
                        region=account["location"],
                        name=account["name"],
                        raw_data=account,
                    )
                )

        # Virtual Machines
        if not resource_types or "virtual_machine" in resource_types:
            for vm in fixtures.get("virtual_machines", []):
                resources.append(
                    Resource(
                        id=vm["id"],
                        type="virtual_machine",
                        provider="azure",
                        region=vm["location"],
                        name=vm["name"],
                        raw_data=vm,
                    )
                )

        return resources


# =============================================================================
# GCP Mock Collector
# =============================================================================


class MockGCPCollector(MockCollectorBase):
    """Mock GCP collector for testing."""

    PROVIDER = "gcp"
    PLATFORM = "gcp"

    DEFAULT_FIXTURES = {
        "instances": [
            {
                "id": "123456789",
                "name": "instance-1",
                "zone": "us-central1-a",
                "machineType": "n1-standard-1",
                "status": "RUNNING",
            },
        ],
        "buckets": [
            {
                "name": "test-bucket-gcp",
                "location": "US",
                "storageClass": "STANDARD",
                "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
            },
        ],
    }

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
        projects: list[str] | None = None,
    ) -> list[Resource]:
        """Collect mock GCP resources."""
        if self._should_fail():
            raise RuntimeError("Mock failure triggered")

        resources = []
        fixtures = {**self.DEFAULT_FIXTURES, **self.fixtures}

        # Compute Instances
        if not resource_types or "compute_instance" in resource_types:
            for instance in fixtures.get("instances", []):
                resources.append(
                    Resource(
                        id=instance["id"],
                        type="compute_instance",
                        provider="gcp",
                        region=instance["zone"],
                        name=instance["name"],
                        raw_data=instance,
                    )
                )

        # Storage Buckets
        if not resource_types or "storage_bucket" in resource_types:
            for bucket in fixtures.get("buckets", []):
                resources.append(
                    Resource(
                        id=bucket["name"],
                        type="storage_bucket",
                        provider="gcp",
                        region=bucket["location"],
                        name=bucket["name"],
                        raw_data=bucket,
                    )
                )

        return resources


# =============================================================================
# Okta Mock Collector
# =============================================================================


class MockOktaCollector(MockCollectorBase):
    """Mock Okta collector for testing."""

    PROVIDER = "okta"
    PLATFORM = "okta"

    DEFAULT_FIXTURES = {
        "users": [
            {
                "id": "00u1234567890",
                "status": "ACTIVE",
                "profile": {
                    "firstName": "Admin",
                    "lastName": "User",
                    "email": "admin@example.com",
                    "login": "admin@example.com",
                },
                "mfaFactors": [
                    {"factorType": "push", "provider": "OKTA"},
                    {"factorType": "token:software:totp", "provider": "OKTA"},
                ],
            },
            {
                "id": "00u0987654321",
                "status": "ACTIVE",
                "profile": {
                    "firstName": "Dev",
                    "lastName": "User",
                    "email": "dev@example.com",
                    "login": "dev@example.com",
                },
                "mfaFactors": [],
            },
        ],
        "groups": [
            {
                "id": "00g1234567890",
                "profile": {"name": "Admins", "description": "Admin group"},
            },
        ],
    }

    def collect_evidence(self) -> CollectionResult:
        """Collect mock Okta evidence."""
        if self._should_fail():
            result = CollectionResult(success=False, platform="okta")
            result.add_error("Mock failure triggered")
            return result

        result = CollectionResult(success=True, platform="okta")
        fixtures = {**self.DEFAULT_FIXTURES, **self.fixtures}

        # Users evidence
        result.add_evidence(
            Evidence(
                id="evidence-okta-users-001",
                platform="okta",
                evidence_type="users",
                collected_at=datetime.now(timezone.utc),
                raw_data={"users": fixtures.get("users", [])},
                metadata={"source": "mock"},
            )
        )

        # Groups evidence
        result.add_evidence(
            Evidence(
                id="evidence-okta-groups-001",
                platform="okta",
                evidence_type="groups",
                collected_at=datetime.now(timezone.utc),
                raw_data={"groups": fixtures.get("groups", [])},
                metadata={"source": "mock"},
            )
        )

        result.complete()
        return result


# =============================================================================
# GitHub Mock Collector
# =============================================================================


class MockGitHubCollector(MockCollectorBase):
    """Mock GitHub collector for testing."""

    PROVIDER = "github"
    PLATFORM = "github"

    DEFAULT_FIXTURES = {
        "repositories": [
            {
                "id": 123456789,
                "name": "test-repo",
                "full_name": "org/test-repo",
                "private": True,
                "default_branch": "main",
                "has_branch_protection": True,
            },
        ],
        "workflows": [
            {
                "id": 987654321,
                "name": "CI",
                "path": ".github/workflows/ci.yml",
                "state": "active",
            },
        ],
    }

    def collect_evidence(self) -> CollectionResult:
        """Collect mock GitHub evidence."""
        if self._should_fail():
            result = CollectionResult(success=False, platform="github")
            result.add_error("Mock failure triggered")
            return result

        result = CollectionResult(success=True, platform="github")
        fixtures = {**self.DEFAULT_FIXTURES, **self.fixtures}

        # Repositories evidence
        result.add_evidence(
            Evidence(
                id="evidence-github-repos-001",
                platform="github",
                evidence_type="repositories",
                collected_at=datetime.now(timezone.utc),
                raw_data={"repositories": fixtures.get("repositories", [])},
                metadata={"source": "mock"},
            )
        )

        result.complete()
        return result


# =============================================================================
# Mock Collector Registry
# =============================================================================


class MockCollectorRegistry:
    """Registry for mock collectors."""

    _collectors: dict[str, type[MockCollectorBase]] = {
        "aws": MockAWSCollector,
        "azure": MockAzureCollector,
        "gcp": MockGCPCollector,
        "okta": MockOktaCollector,
        "github": MockGitHubCollector,
    }

    @classmethod
    def get(cls, provider: str) -> type[MockCollectorBase] | None:
        """Get a mock collector class by provider."""
        return cls._collectors.get(provider)

    @classmethod
    def register(cls, provider: str, collector_class: type[MockCollectorBase]) -> None:
        """Register a mock collector."""
        cls._collectors[provider] = collector_class

    @classmethod
    def list_providers(cls) -> list[str]:
        """List registered providers."""
        return list(cls._collectors.keys())


def create_mock_collector(
    provider: str,
    fixtures: dict[str, Any] | None = None,
    **kwargs: Any,
) -> MockCollectorBase:
    """
    Create a mock collector for a provider.

    Args:
        provider: Provider name (aws, azure, gcp, okta, github).
        fixtures: Optional fixture data.
        **kwargs: Additional arguments for the collector.

    Returns:
        Mock collector instance.

    Raises:
        ValueError: If provider is not supported.
    """
    collector_class = MockCollectorRegistry.get(provider)
    if collector_class is None:
        raise ValueError(f"Unknown provider: {provider}")

    return collector_class(fixtures=fixtures, **kwargs)
