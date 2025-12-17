"""
Pytest configuration and shared fixtures for Attestful tests.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

from attestful.core.models import Resource, Evidence, CollectionResult


# =============================================================================
# Directory Fixtures
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory that is cleaned up after the test."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_evidence_dir(temp_dir):
    """Create a temporary evidence directory."""
    evidence_path = temp_dir / "evidence"
    evidence_path.mkdir()
    return evidence_path


@pytest.fixture
def temp_data_dir(temp_dir):
    """Create a temporary data directory."""
    data_path = temp_dir / "data"
    data_path.mkdir()
    return data_path


# =============================================================================
# AWS Resource Fixtures
# =============================================================================


@pytest.fixture
def aws_s3_bucket():
    """Sample AWS S3 bucket resource."""
    return Resource(
        id="arn:aws:s3:::test-bucket",
        type="s3_bucket",
        provider="aws",
        region="us-east-1",
        name="test-bucket",
        raw_data={
            "Name": "test-bucket",
            "CreationDate": "2024-01-01T00:00:00Z",
            "Encryption": {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            },
            "Versioning": {"Status": "Enabled"},
            "PublicAccessBlock": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                }
            },
            "Logging": {
                "TargetBucket": "logs-bucket",
                "TargetPrefix": "s3-access-logs/",
            },
        },
        tags={"Environment": "production", "Team": "security"},
    )


@pytest.fixture
def aws_ec2_instance():
    """Sample AWS EC2 instance resource."""
    return Resource(
        id="i-1234567890abcdef0",
        type="ec2_instance",
        provider="aws",
        region="us-west-2",
        name="web-server-01",
        raw_data={
            "InstanceId": "i-1234567890abcdef0",
            "InstanceType": "t3.medium",
            "State": {"Name": "running"},
            "MetadataOptions": {
                "HttpTokens": "required",
                "HttpEndpoint": "enabled",
            },
            "IamInstanceProfile": {
                "Arn": "arn:aws:iam::123456789012:instance-profile/web-server-role"
            },
            "SecurityGroups": [
                {"GroupId": "sg-12345678", "GroupName": "web-server-sg"}
            ],
            "VpcId": "vpc-12345678",
            "SubnetId": "subnet-12345678",
            "PublicIpAddress": None,
            "PrivateIpAddress": "10.0.1.100",
        },
        tags={"Name": "web-server-01", "Environment": "production"},
    )


@pytest.fixture
def aws_iam_user():
    """Sample AWS IAM user resource."""
    return Resource(
        id="arn:aws:iam::123456789012:user/admin",
        type="iam_user",
        provider="aws",
        name="admin",
        raw_data={
            "UserName": "admin",
            "UserId": "AIDAEXAMPLEID",
            "Arn": "arn:aws:iam::123456789012:user/admin",
            "CreateDate": "2024-01-01T00:00:00Z",
            "MFADevices": [
                {
                    "UserName": "admin",
                    "SerialNumber": "arn:aws:iam::123456789012:mfa/admin",
                    "EnableDate": "2024-01-02T00:00:00Z",
                }
            ],
            "AccessKeys": [
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "Status": "Active",
                    "CreateDate": "2024-01-01T00:00:00Z",
                }
            ],
            "PasswordLastUsed": "2024-06-01T10:30:00Z",
        },
    )


@pytest.fixture
def aws_rds_instance():
    """Sample AWS RDS instance resource."""
    return Resource(
        id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
        type="rds_instance",
        provider="aws",
        region="us-east-1",
        name="prod-db",
        raw_data={
            "DBInstanceIdentifier": "prod-db",
            "DBInstanceClass": "db.r5.large",
            "Engine": "postgres",
            "EngineVersion": "14.7",
            "StorageEncrypted": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/mrk-12345",
            "PubliclyAccessible": False,
            "MultiAZ": True,
            "VpcSecurityGroups": [
                {"VpcSecurityGroupId": "sg-database", "Status": "active"}
            ],
            "BackupRetentionPeriod": 30,
            "DeletionProtection": True,
        },
        tags={"Environment": "production", "DataClassification": "confidential"},
    )


@pytest.fixture
def aws_security_group():
    """Sample AWS security group resource."""
    return Resource(
        id="sg-12345678",
        type="ec2_security_group",
        provider="aws",
        region="us-east-1",
        name="web-server-sg",
        raw_data={
            "GroupId": "sg-12345678",
            "GroupName": "web-server-sg",
            "Description": "Security group for web servers",
            "VpcId": "vpc-12345678",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                },
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        },
    )


# =============================================================================
# Evidence Fixtures
# =============================================================================


@pytest.fixture
def aws_iam_evidence():
    """Sample AWS IAM credential report evidence."""
    return Evidence(
        id="evidence-iam-001",
        platform="aws",
        evidence_type="iam_credential_report",
        collected_at=datetime.now(timezone.utc),
        raw_data={
            "report_format": "csv",
            "generated_time": "2024-06-15T10:00:00Z",
            "users": [
                {
                    "user": "admin",
                    "user_creation_time": "2024-01-01T00:00:00Z",
                    "password_enabled": "true",
                    "password_last_used": "2024-06-15T08:00:00Z",
                    "mfa_active": "true",
                    "access_key_1_active": "true",
                    "access_key_1_last_used_date": "2024-06-14T12:00:00Z",
                },
                {
                    "user": "developer",
                    "user_creation_time": "2024-02-01T00:00:00Z",
                    "password_enabled": "true",
                    "password_last_used": "2024-06-15T09:00:00Z",
                    "mfa_active": "false",
                    "access_key_1_active": "true",
                    "access_key_1_last_used_date": "2024-06-15T10:00:00Z",
                },
            ],
        },
        metadata={
            "account_id": "123456789012",
            "region": "global",
            "collection_method": "automated",
            "source": "collector:aws",
        },
    )


@pytest.fixture
def okta_users_evidence():
    """Sample Okta users evidence."""
    return Evidence(
        id="evidence-okta-001",
        platform="okta",
        evidence_type="users",
        collected_at=datetime.now(timezone.utc),
        raw_data={
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
                    "credentials": {
                        "provider": {
                            "type": "OKTA",
                            "name": "OKTA",
                        }
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
                    "credentials": {
                        "provider": {
                            "type": "OKTA",
                            "name": "OKTA",
                        }
                    },
                    "mfaFactors": [],
                },
            ],
            "total_users": 2,
        },
        metadata={
            "org_url": "https://example.okta.com",
            "collection_method": "automated",
            "source": "collector:okta",
        },
    )


# =============================================================================
# Collection Result Fixtures
# =============================================================================


@pytest.fixture
def successful_collection_result(aws_iam_evidence):
    """Sample successful collection result."""
    result = CollectionResult(
        success=True,
        platform="aws",
    )
    result.add_evidence(aws_iam_evidence)
    result.complete()
    return result


@pytest.fixture
def partial_collection_result(aws_iam_evidence):
    """Sample partial collection result with errors."""
    result = CollectionResult(
        success=True,
        partial=True,
        platform="aws",
    )
    result.add_evidence(aws_iam_evidence)
    result.add_error("Failed to collect S3 bucket inventory")
    result.add_warning("API rate limit approaching")
    result.complete()
    return result


@pytest.fixture
def failed_collection_result():
    """Sample failed collection result."""
    result = CollectionResult(
        success=False,
        platform="aws",
    )
    result.add_error("Authentication failed: Invalid credentials")
    result.complete()
    return result


# =============================================================================
# Check Result Fixtures
# =============================================================================


@pytest.fixture
def sample_check_results():
    """Sample check results for testing."""
    from attestful.core.evaluator import CheckDefinition, Condition, Operator

    check = CheckDefinition(
        id="s3-encryption",
        title="S3 Encryption",
        description="Check S3 bucket encryption",
        severity="high",
        resource_types=["s3_bucket"],
        condition=Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
        frameworks={"soc2": ["CC6.1"]},
    )

    # Would need to import CheckResult from evaluator
    return []


# =============================================================================
# Evaluator Fixtures
# =============================================================================


@pytest.fixture
def default_evaluator():
    """Create default evaluator with built-in checks."""
    from attestful.core.evaluator import create_default_evaluator

    return create_default_evaluator()


# =============================================================================
# Test Configuration
# =============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
