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
    config.addinivalue_line(
        "markers", "security: marks security-related tests"
    )
    config.addinivalue_line(
        "markers", "oscal: marks OSCAL-related tests"
    )
    config.addinivalue_line(
        "markers", "collector: marks collector tests"
    )
    config.addinivalue_line(
        "markers", "offline: marks offline/air-gap tests"
    )


# =============================================================================
# Database Fixtures
# =============================================================================


@pytest.fixture
def temp_db_path(temp_dir):
    """Create a temporary database file path."""
    return temp_dir / "test_attestful.db"


@pytest.fixture
def test_db_engine(temp_db_path):
    """Create a test database engine."""
    from sqlalchemy import create_engine
    from attestful.storage.models import Base

    engine = create_engine(f"sqlite:///{temp_db_path}", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def test_db_session(test_db_engine):
    """Create a test database session."""
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=test_db_engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def sample_organization(test_db_session):
    """Create a sample organization in the database."""
    from attestful.storage.models import Organization

    org = Organization(
        id="org-test-001",
        name="Test Organization",
        display_name="Test Org",
        settings={"timezone": "UTC"},
    )
    test_db_session.add(org)
    test_db_session.commit()
    return org


@pytest.fixture
def sample_user(test_db_session, sample_organization):
    """Create a sample user in the database."""
    from attestful.storage.models import User

    user = User(
        id="user-test-001",
        organization_id=sample_organization.id,
        email="test@example.com",
        name="Test User",
        role="admin",
    )
    test_db_session.add(user)
    test_db_session.commit()
    return user


# =============================================================================
# OSCAL Document Fixtures
# =============================================================================


@pytest.fixture
def sample_oscal_catalog():
    """Create a sample OSCAL catalog."""
    from attestful.oscal.models import (
        Catalog,
        Metadata,
        Group,
        Control,
        Part,
    )

    return Catalog(
        uuid="catalog-test-001",
        metadata=Metadata(
            title="Test Catalog",
            version="1.0.0",
            oscal_version="1.1.0",
        ),
        groups=[
            Group(
                id="group-ac",
                title="Access Control",
                controls=[
                    Control(
                        id="ac-1",
                        title="Access Control Policy and Procedures",
                        parts=[
                            Part(
                                id="ac-1_smt",
                                name="statement",
                                prose="The organization develops, documents, and disseminates access control policy.",
                            ),
                        ],
                    ),
                    Control(
                        id="ac-2",
                        title="Account Management",
                        parts=[
                            Part(
                                id="ac-2_smt",
                                name="statement",
                                prose="The organization manages information system accounts.",
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


@pytest.fixture
def sample_oscal_profile():
    """Create a sample OSCAL profile."""
    from attestful.oscal.models import (
        Profile,
        Metadata,
        Import,
    )

    return Profile(
        uuid="profile-test-001",
        metadata=Metadata(
            title="Test Profile",
            version="1.0.0",
            oscal_version="1.1.0",
        ),
        imports=[
            Import(
                href="catalog-test-001",
                include_controls=[
                    {"with_ids": ["ac-1", "ac-2"]},
                ],
            ),
        ],
    )


@pytest.fixture
def sample_oscal_ssp():
    """Create a sample OSCAL SSP."""
    from attestful.oscal.models import (
        SystemSecurityPlan,
        Metadata,
        SystemCharacteristics,
        SystemId,
        SystemStatus,
        ImportProfile,
    )

    return SystemSecurityPlan(
        uuid="ssp-test-001",
        metadata=Metadata(
            title="Test System Security Plan",
            version="1.0.0",
            oscal_version="1.1.0",
        ),
        import_profile=ImportProfile(href="profile-test-001"),
        system_characteristics=SystemCharacteristics(
            system_name="Test System",
            description="A test system for unit testing",
            system_ids=[
                SystemId(
                    identifier_type="https://attestful.dev",
                    id="test-system-001",
                ),
            ],
            status=SystemStatus(state="operational"),
        ),
    )


# =============================================================================
# Credential Fixtures
# =============================================================================


@pytest.fixture
def temp_credential_store(temp_dir):
    """Create a temporary credential store."""
    from attestful.config.credentials import CredentialStore

    store = CredentialStore(
        data_dir=temp_dir / "credentials",
        key_file=temp_dir / "credentials" / ".key",
        credentials_file=temp_dir / "credentials" / "credentials.enc",
    )
    return store


@pytest.fixture
def sample_aws_credentials():
    """Sample AWS credentials for testing."""
    return {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
    }


@pytest.fixture
def sample_okta_credentials():
    """Sample Okta credentials for testing."""
    return {
        "domain": "example.okta.com",
        "api_token": "00abc123DEF456ghi789JKL",
    }


# =============================================================================
# Mock Response Fixtures
# =============================================================================


@pytest.fixture
def mock_aws_s3_response():
    """Mock AWS S3 ListBuckets response."""
    return {
        "Buckets": [
            {
                "Name": "test-bucket-1",
                "CreationDate": "2024-01-01T00:00:00Z",
            },
            {
                "Name": "test-bucket-2",
                "CreationDate": "2024-02-01T00:00:00Z",
            },
        ],
        "Owner": {
            "DisplayName": "test-account",
            "ID": "abc123",
        },
    }


@pytest.fixture
def mock_okta_users_response():
    """Mock Okta Users API response."""
    return [
        {
            "id": "00u1234567890",
            "status": "ACTIVE",
            "created": "2024-01-01T00:00:00.000Z",
            "profile": {
                "firstName": "Test",
                "lastName": "User",
                "email": "test@example.com",
                "login": "test@example.com",
            },
        },
        {
            "id": "00u0987654321",
            "status": "ACTIVE",
            "created": "2024-02-01T00:00:00.000Z",
            "profile": {
                "firstName": "Another",
                "lastName": "User",
                "email": "another@example.com",
                "login": "another@example.com",
            },
        },
    ]


# =============================================================================
# Framework Fixtures
# =============================================================================


@pytest.fixture
def sample_soc2_controls():
    """Sample SOC 2 Trust Services Criteria."""
    return [
        {
            "id": "CC1.1",
            "title": "Control Environment",
            "description": "The entity demonstrates a commitment to integrity and ethical values.",
            "category": "CC1",
        },
        {
            "id": "CC6.1",
            "title": "Logical and Physical Access Controls",
            "description": "The entity implements logical access security software.",
            "category": "CC6",
        },
    ]


@pytest.fixture
def sample_nist_csf_controls():
    """Sample NIST CSF 2.0 controls."""
    return [
        {
            "id": "ID.AM-1",
            "title": "Asset Management",
            "description": "Physical devices and systems are inventoried.",
            "function": "IDENTIFY",
            "category": "Asset Management",
        },
        {
            "id": "PR.AC-1",
            "title": "Access Control",
            "description": "Identities and credentials are issued and managed.",
            "function": "PROTECT",
            "category": "Identity Management",
        },
    ]


# =============================================================================
# Scan Result Fixtures
# =============================================================================


@pytest.fixture
def sample_scan_results():
    """Sample scan results for testing."""
    return {
        "scan_id": "scan-test-001",
        "provider": "aws",
        "started_at": "2024-06-15T10:00:00Z",
        "completed_at": "2024-06-15T10:05:00Z",
        "status": "completed",
        "resources_scanned": 100,
        "findings": {
            "critical": 2,
            "high": 5,
            "medium": 10,
            "low": 20,
            "passed": 63,
        },
    }


@pytest.fixture
def sample_maturity_scores():
    """Sample maturity scores for testing."""
    return {
        "framework": "nist_csf_2",
        "overall_score": 3.5,
        "function_scores": {
            "IDENTIFY": 3.8,
            "PROTECT": 3.6,
            "DETECT": 3.2,
            "RESPOND": 3.4,
            "RECOVER": 3.5,
        },
        "category_scores": {
            "ID.AM": 4.0,
            "ID.BE": 3.5,
            "PR.AC": 3.8,
            "PR.DS": 3.4,
        },
    }
