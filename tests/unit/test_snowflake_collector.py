"""
Unit tests for Snowflake collector.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from attestful.collectors.platforms.snowflake import (
    SnowflakeCollector,
    SnowflakeCollectorConfig,
    EVIDENCE_CONTROL_MAPPINGS,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Snowflake configuration."""
    return SnowflakeCollectorConfig(
        account="xy12345.us-east-1",
        user="admin",
        password="test-password",
        warehouse="COMPUTE_WH",
        database="PROD_DB",
        role="ACCOUNTADMIN",
        timeout=60,
        days_of_history=30,
        query_limit=1000,
    )


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "name": "ADMIN_USER",
        "login_name": "admin@example.com",
        "display_name": "Admin User",
        "email": "admin@example.com",
        "disabled": "false",
        "locked": "false",
        "default_role": "SYSADMIN",
        "default_warehouse": "COMPUTE_WH",
        "created_on": datetime(2024, 1, 1, 10, 0, 0),
        "last_success_login": datetime(2024, 3, 15, 14, 30, 0),
        "ext_authn_duo": "true",
        "has_mfa": "true",
        "has_password": "true",
        "has_rsa_public_key": "false",
        "comment": "Primary admin user",
    }


@pytest.fixture
def mock_service_account():
    """Create a mock service account user."""
    return {
        "name": "SVC_ETL_USER",
        "login_name": "svc_etl",
        "display_name": "ETL Service Account",
        "email": "",
        "disabled": "false",
        "locked": "false",
        "default_role": "ETL_ROLE",
        "default_warehouse": "ETL_WH",
        "created_on": datetime(2024, 1, 15, 8, 0, 0),
        "last_success_login": datetime(2024, 3, 15, 12, 0, 0),
        "ext_authn_duo": "false",
        "has_mfa": "false",
        "has_password": "false",
        "has_rsa_public_key": "true",
        "comment": "ETL service account",
    }


@pytest.fixture
def mock_role():
    """Create a mock role response."""
    return {
        "name": "DATA_ANALYST",
        "comment": "Role for data analysts",
        "created_on": datetime(2024, 1, 1, 9, 0, 0),
        "owner": "USERADMIN",
        "assigned_to_users": 5,
        "granted_to_roles": 2,
        "granted_roles": 1,
        "is_default": "false",
        "is_current": "false",
        "is_inherited": "false",
    }


@pytest.fixture
def mock_warehouse():
    """Create a mock warehouse response."""
    return {
        "name": "COMPUTE_WH",
        "state": "STARTED",
        "size": "X-SMALL",
        "type": "STANDARD",
        "created_on": datetime(2024, 1, 1, 8, 0, 0),
        "auto_suspend": 300,
        "auto_resume": "true",
        "available": 1,
        "provisioning": 0,
        "running": 1,
        "queued": 0,
        "min_cluster_count": 1,
        "max_cluster_count": 1,
        "scaling_policy": "STANDARD",
        "owner": "SYSADMIN",
        "comment": "Main compute warehouse",
        "resource_monitor": "COMPUTE_MONITOR",
    }


@pytest.fixture
def mock_database():
    """Create a mock database response."""
    return {
        "name": "PROD_DB",
        "created_on": datetime(2024, 1, 1, 8, 0, 0),
        "owner": "SYSADMIN",
        "comment": "Production database",
        "options": "TRANSIENT=false",
        "retention_time": 7,
        "transient": "false",
        "origin": "",
        "is_default": "false",
        "is_current": "true",
    }


@pytest.fixture
def mock_login_event():
    """Create a mock login event."""
    return {
        "user_name": "ADMIN_USER",
        "event_type": "LOGIN",
        "is_success": "YES",
        "client_ip": "192.168.1.100",
        "reported_client_type": "JDBC_DRIVER",
        "reported_client_version": "3.13.30",
        "first_authentication_factor": "PASSWORD",
        "second_authentication_factor": "DUO_PUSH",
        "event_timestamp": datetime(2024, 3, 15, 14, 30, 0),
        "error_code": None,
        "error_message": None,
    }


@pytest.fixture
def mock_query():
    """Create a mock query history entry."""
    return {
        "query_id": "01b12345-0001-1234-0000-000000000001",
        "query_type": "SELECT",
        "user_name": "ADMIN_USER",
        "role_name": "SYSADMIN",
        "database_name": "PROD_DB",
        "schema_name": "PUBLIC",
        "warehouse_name": "COMPUTE_WH",
        "execution_status": "SUCCESS",
        "error_code": None,
        "error_message": None,
        "start_time": datetime(2024, 3, 15, 14, 0, 0),
        "end_time": datetime(2024, 3, 15, 14, 0, 5),
        "total_elapsed_time": 5000,
        "bytes_scanned": 1000000,
        "rows_produced": 100,
        "credits_used_cloud_services": 0.001,
    }


@pytest.fixture
def mock_grant():
    """Create a mock grant entry."""
    return {
        "privilege": "SELECT",
        "granted_on": "TABLE",
        "name": "USERS_TABLE",
        "table_catalog": "PROD_DB",
        "table_schema": "PUBLIC",
        "grantee_name": "DATA_ANALYST",
        "grant_option": "false",
        "granted_by": "SYSADMIN",
        "created_on": datetime(2024, 2, 1, 10, 0, 0),
    }


@pytest.fixture
def mock_network_policy():
    """Create a mock network policy."""
    return {
        "name": "CORP_NETWORK_POLICY",
        "created_on": datetime(2024, 1, 1, 8, 0, 0),
        "comment": "Corporate network policy",
        "entries_in_allowed_ip_list": 3,
        "entries_in_blocked_ip_list": 1,
    }


# =============================================================================
# Configuration Tests
# =============================================================================


class TestSnowflakeCollectorConfig:
    """Tests for Snowflake collector configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SnowflakeCollectorConfig()
        assert config.account == ""
        assert config.user == ""
        assert config.password == ""
        assert config.warehouse == ""
        assert config.database == ""
        assert config.role == ""
        assert config.private_key_path == ""
        assert config.private_key_passphrase == ""
        assert config.timeout == 60
        assert config.days_of_history == 30
        assert config.query_limit == 1000

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.account == "xy12345.us-east-1"
        assert mock_config.user == "admin"
        assert mock_config.password == "test-password"
        assert mock_config.warehouse == "COMPUTE_WH"
        assert mock_config.database == "PROD_DB"
        assert mock_config.role == "ACCOUNTADMIN"

    def test_key_pair_config(self):
        """Test key-pair authentication configuration."""
        config = SnowflakeCollectorConfig(
            account="xy12345",
            user="admin",
            private_key_path="/path/to/key.pem",
            private_key_passphrase="secret",
        )
        assert config.private_key_path == "/path/to/key.pem"
        assert config.private_key_passphrase == "secret"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestSnowflakeCollectorInit:
    """Tests for Snowflake collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = SnowflakeCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "snowflake"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = SnowflakeCollector()
        assert collector.config is not None
        assert collector.config.account == ""

    def test_supported_resource_types(self, mock_config):
        """Test supported resource types."""
        collector = SnowflakeCollector(config=mock_config)
        assert "snowflake_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "snowflake_role" in collector.SUPPORTED_RESOURCE_TYPES
        assert "snowflake_warehouse" in collector.SUPPORTED_RESOURCE_TYPES
        assert "snowflake_database" in collector.SUPPORTED_RESOURCE_TYPES

    def test_supported_evidence_types(self, mock_config):
        """Test supported evidence types."""
        collector = SnowflakeCollector(config=mock_config)
        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "roles" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "warehouses" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "databases" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "access_history" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "query_history" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "grants" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "network_policies" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Metadata Tests
# =============================================================================


class TestMetadata:
    """Tests for collector metadata."""

    def test_get_metadata(self, mock_config):
        """Test getting collector metadata."""
        collector = SnowflakeCollector(config=mock_config)
        metadata = collector.get_metadata()

        assert metadata.name == "Snowflake Collector"
        assert metadata.platform == "snowflake"
        assert "snowflake_user" in metadata.resource_types
        assert "users" in metadata.evidence_types
        assert metadata.version == "1.0.0"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._get_connection")
    def test_validate_credentials_success(self, mock_get_conn, mock_config):
        """Test successful credential validation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("ADMIN_USER", "ACCOUNTADMIN", "xy12345")
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        collector = SnowflakeCollector(config=mock_config)
        result = collector.validate_credentials()

        assert result is True
        mock_cursor.execute.assert_called_once()

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._get_connection")
    def test_validate_credentials_failure(self, mock_get_conn, mock_config):
        """Test failed credential validation."""
        mock_get_conn.side_effect = Exception("Connection failed")

        collector = SnowflakeCollector(config=mock_config)
        result = collector.validate_credentials()

        assert result is False

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._get_connection")
    def test_validate_credentials_empty_result(self, mock_get_conn, mock_config):
        """Test credential validation with empty result."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        collector = SnowflakeCollector(config=mock_config)
        result = collector.validate_credentials()

        assert result is False


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_users(self, mock_execute, mock_config, mock_user):
        """Test collecting user resources."""
        mock_execute.return_value = [mock_user]

        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["snowflake_user"])

        assert len(resources) == 1
        assert resources[0].type == "snowflake_user"
        assert resources[0].name == "ADMIN_USER"
        assert resources[0].tags["disabled"] == "false"

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_roles(self, mock_execute, mock_config, mock_role):
        """Test collecting role resources."""
        mock_execute.return_value = [mock_role]

        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["snowflake_role"])

        assert len(resources) == 1
        assert resources[0].type == "snowflake_role"
        assert resources[0].name == "DATA_ANALYST"
        assert resources[0].metadata["owner"] == "USERADMIN"

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_warehouses(self, mock_execute, mock_config, mock_warehouse):
        """Test collecting warehouse resources."""
        mock_execute.return_value = [mock_warehouse]

        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["snowflake_warehouse"])

        assert len(resources) == 1
        assert resources[0].type == "snowflake_warehouse"
        assert resources[0].name == "COMPUTE_WH"
        assert resources[0].tags["state"] == "STARTED"
        assert resources[0].tags["size"] == "X-SMALL"

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_databases(self, mock_execute, mock_config, mock_database):
        """Test collecting database resources."""
        mock_execute.return_value = [mock_database]

        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["snowflake_database"])

        assert len(resources) == 1
        assert resources[0].type == "snowflake_database"
        assert resources[0].name == "PROD_DB"
        assert resources[0].metadata["owner"] == "SYSADMIN"

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_all_resources(self, mock_execute, mock_config, mock_user, mock_role, mock_warehouse, mock_database):
        """Test collecting all resource types."""
        mock_execute.side_effect = [
            [mock_user],
            [mock_role],
            [mock_warehouse],
            [mock_database],
        ]

        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources()

        assert len(resources) == 4


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_users_evidence(self, mock_execute, mock_config, mock_user, mock_service_account):
        """Test collecting users evidence."""
        mock_execute.return_value = [mock_user, mock_service_account]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "users"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["mfa_enabled"] == 1
        assert evidence.raw_data["summary"]["service_accounts"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_users_mfa_rate(self, mock_execute, mock_config, mock_user, mock_service_account):
        """Test MFA rate calculation in users evidence."""
        mock_execute.return_value = [mock_user, mock_service_account]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        summary = evidence.raw_data["summary"]
        # 1 user with MFA out of 2 active users = 50%
        assert summary["mfa_rate_percent"] == 50.0

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_roles_evidence(self, mock_execute, mock_config, mock_role):
        """Test collecting roles evidence."""
        system_role = {
            "name": "ACCOUNTADMIN",
            "comment": "System admin role",
            "created_on": datetime(2020, 1, 1),
            "owner": "ACCOUNTADMIN",
            "assigned_to_users": 1,
            "granted_to_roles": 0,
            "granted_roles": 5,
            "is_default": "false",
            "is_current": "true",
            "is_inherited": "false",
        }
        mock_execute.side_effect = [[mock_role, system_role], []]  # roles, then role hierarchy

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["roles"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "roles"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["system_roles"] == 1
        assert evidence.raw_data["summary"]["custom_roles"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_warehouses_evidence(self, mock_execute, mock_config, mock_warehouse):
        """Test collecting warehouses evidence."""
        suspended_warehouse = mock_warehouse.copy()
        suspended_warehouse["name"] = "SUSPENDED_WH"
        suspended_warehouse["state"] = "SUSPENDED"

        mock_execute.side_effect = [[mock_warehouse, suspended_warehouse], []]  # warehouses, then usage

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["warehouses"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "warehouses"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["running"] == 1
        assert evidence.raw_data["summary"]["suspended"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_databases_evidence(self, mock_execute, mock_config, mock_database):
        """Test collecting databases evidence."""
        transient_db = mock_database.copy()
        transient_db["name"] = "TEMP_DB"
        transient_db["transient"] = "true"

        mock_execute.return_value = [mock_database, transient_db]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["databases"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "databases"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["transient_databases"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_access_history_evidence(self, mock_execute, mock_config, mock_login_event):
        """Test collecting access history evidence."""
        failed_login = mock_login_event.copy()
        failed_login["is_success"] = "NO"
        failed_login["error_code"] = "AUTH_ERROR"
        failed_login["error_message"] = "Invalid password"

        mock_execute.return_value = [mock_login_event, failed_login]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["access_history"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "access_history"
        assert evidence.raw_data["total_events"] == 2
        assert evidence.raw_data["summary"]["successful_logins"] == 1
        assert evidence.raw_data["summary"]["failed_logins"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_query_history_evidence(self, mock_execute, mock_config, mock_query):
        """Test collecting query history evidence."""
        failed_query = mock_query.copy()
        failed_query["query_id"] = "01b12345-0001-1234-0000-000000000002"
        failed_query["execution_status"] = "FAIL"
        failed_query["error_code"] = "100051"
        failed_query["error_message"] = "Object does not exist"

        mock_execute.return_value = [mock_query, failed_query]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["query_history"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "query_history"
        assert evidence.raw_data["total_queries"] == 2
        assert evidence.raw_data["summary"]["failed_queries"] == 1
        assert evidence.raw_data["summary"]["success_rate_percent"] == 50.0

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_grants_evidence(self, mock_execute, mock_config, mock_grant):
        """Test collecting grants evidence."""
        ownership_grant = mock_grant.copy()
        ownership_grant["privilege"] = "OWNERSHIP"
        ownership_grant["name"] = "ANALYTICS_SCHEMA"

        mock_execute.side_effect = [[mock_grant, ownership_grant], []]  # grants to roles, then grants to users

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["grants"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "grants"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["high_privilege_grants"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_collect_network_policies_evidence(self, mock_execute, mock_config, mock_network_policy):
        """Test collecting network policies evidence."""
        mock_execute.side_effect = [
            [mock_network_policy],  # SHOW NETWORK POLICIES
            [{"name": "ALLOWED_IP_LIST", "value": "192.168.1.0/24,10.0.0.0/8"}],  # DESCRIBE
            [{"key": "NETWORK_POLICY", "value": "CORP_NETWORK_POLICY"}],  # SHOW PARAMETERS
        ]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["network_policies"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "network_policies"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["account_network_policy"] == "CORP_NETWORK_POLICY"
        assert evidence.raw_data["summary"]["account_policy_enabled"] is True


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_resource_collection_error(self, mock_execute, mock_config):
        """Test handling errors during resource collection."""
        mock_execute.side_effect = Exception("Query failed")

        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["snowflake_user"])

        # Should return empty list, not raise
        assert resources == []

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_evidence_collection_error(self, mock_execute, mock_config):
        """Test handling errors during evidence collection.

        Snowflake collector handles query errors gracefully - individual evidence
        methods catch exceptions and return empty data rather than failing
        completely. This ensures partial collection still works.
        """
        mock_execute.side_effect = Exception("Query failed")

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        # Should still return evidence (with empty data), not fail
        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        # Data should be empty due to error
        assert result.evidence_items[0].raw_data["total_count"] == 0

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_partial_evidence_collection(self, mock_execute, mock_config, mock_user, mock_role):
        """Test partial evidence collection when some queries fail.

        Snowflake collector handles query errors gracefully - individual evidence
        methods catch exceptions and return empty data rather than failing
        completely. This ensures partial collection still works.
        """
        mock_execute.side_effect = [
            [mock_user],  # users succeeds
            Exception("Roles query failed"),  # roles fails (returns empty data)
            [],  # role hierarchy also fails gracefully
        ]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users", "roles"])

        # Both evidence types should be returned (roles with empty data)
        assert len(result.evidence_items) == 2
        users_evidence = next(e for e in result.evidence_items if e.evidence_type == "users")
        roles_evidence = next(e for e in result.evidence_items if e.evidence_type == "roles")
        assert users_evidence.raw_data["total_count"] == 1
        assert roles_evidence.raw_data["total_count"] == 0  # Empty due to error

    def test_unknown_resource_type(self, mock_config):
        """Test handling unknown resource types."""
        collector = SnowflakeCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["unknown_type"])
        assert resources == []

    def test_unknown_evidence_type(self, mock_config):
        """Test handling unknown evidence types."""
        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["unknown_type"])
        assert len(result.evidence_items) == 0


# =============================================================================
# Compliance Metadata Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance-related metadata in evidence."""

    def test_evidence_control_mappings(self):
        """Test evidence control mappings are defined."""
        assert "users" in EVIDENCE_CONTROL_MAPPINGS
        assert "roles" in EVIDENCE_CONTROL_MAPPINGS
        assert "grants" in EVIDENCE_CONTROL_MAPPINGS
        assert "access_history" in EVIDENCE_CONTROL_MAPPINGS
        assert "query_history" in EVIDENCE_CONTROL_MAPPINGS
        assert "network_policies" in EVIDENCE_CONTROL_MAPPINGS

    def test_users_compliance_controls(self):
        """Test compliance controls for users evidence."""
        controls = EVIDENCE_CONTROL_MAPPINGS["users"]
        assert "SOC2:CC6.1" in controls
        assert "NIST:AC-2" in controls
        assert "ISO27001:A.9.2" in controls
        assert "HITRUST:01.b" in controls

    def test_access_history_compliance_controls(self):
        """Test compliance controls for access history evidence."""
        controls = EVIDENCE_CONTROL_MAPPINGS["access_history"]
        assert "SOC2:CC7.2" in controls
        assert "NIST:AU-2" in controls
        assert "ISO27001:A.12.4" in controls
        assert "HITRUST:09.ab" in controls

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_evidence_contains_compliance_controls(self, mock_execute, mock_config, mock_user):
        """Test that evidence contains compliance controls."""
        mock_execute.return_value = [mock_user]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        assert "compliance_controls" in evidence.metadata
        assert "SOC2:CC6.1" in evidence.metadata["compliance_controls"]


# =============================================================================
# Service Account Detection Tests
# =============================================================================


class TestServiceAccountDetection:
    """Tests for service account detection logic."""

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_detect_service_account_by_name(self, mock_execute, mock_config):
        """Test detecting service accounts by name pattern."""
        svc_user = {
            "name": "SVC_DATA_PIPELINE",
            "login_name": "svc_pipeline",
            "display_name": "Data Pipeline Service",
            "email": "pipeline@example.com",
            "disabled": "false",
            "locked": "false",
            "default_role": "ETL_ROLE",
            "created_on": datetime(2024, 1, 1),
            "last_success_login": datetime(2024, 3, 15),
            "ext_authn_duo": "false",
            "has_mfa": "false",
            "has_password": "true",
            "has_rsa_public_key": "false",
        }
        mock_execute.return_value = [svc_user]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        assert evidence.raw_data["summary"]["service_accounts"] == 1

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_detect_service_account_no_email(self, mock_execute, mock_config):
        """Test detecting service accounts without email."""
        bot_user = {
            "name": "BOT_REPORTER",
            "login_name": "bot_reporter",
            "display_name": "Reporter Bot",
            "email": "",
            "disabled": "false",
            "locked": "false",
            "default_role": "REPORTER",
            "created_on": datetime(2024, 1, 1),
            "last_success_login": datetime(2024, 3, 15),
            "ext_authn_duo": "false",
            "has_mfa": "false",
            "has_password": "true",
            "has_rsa_public_key": "false",
        }
        mock_execute.return_value = [bot_user]

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        assert evidence.raw_data["summary"]["service_accounts"] == 1


# =============================================================================
# Suspicious Activity Detection Tests
# =============================================================================


class TestSuspiciousActivityDetection:
    """Tests for suspicious activity detection."""

    @patch("attestful.collectors.platforms.snowflake.SnowflakeCollector._execute_query")
    def test_detect_suspicious_failed_logins(self, mock_execute, mock_config):
        """Test detecting users with high failed login counts."""
        # Create multiple failed login events for same user
        failed_events = []
        for i in range(6):
            failed_events.append({
                "user_name": "SUSPICIOUS_USER",
                "event_type": "LOGIN",
                "is_success": "NO",
                "client_ip": f"192.168.1.{i}",
                "reported_client_type": "JDBC_DRIVER",
                "reported_client_version": "3.13.30",
                "first_authentication_factor": "PASSWORD",
                "second_authentication_factor": None,
                "event_timestamp": datetime(2024, 3, 15, 14, i, 0),
                "error_code": "AUTH_ERROR",
                "error_message": "Invalid password",
            })

        mock_execute.return_value = failed_events

        collector = SnowflakeCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["access_history"])

        evidence = result.evidence_items[0]
        assert len(evidence.raw_data["suspicious_users"]) == 1
        assert evidence.raw_data["suspicious_users"][0]["user"] == "SUSPICIOUS_USER"
        assert evidence.raw_data["suspicious_users"][0]["failed_attempts"] == 6


# =============================================================================
# CLI Tests
# =============================================================================


class TestSnowflakeCLI:
    """Tests for Snowflake CLI commands."""

    def test_snowflake_help(self):
        """Test snowflake collect help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "snowflake", "--help"])
        assert result.exit_code == 0
        assert "Collect evidence from Snowflake" in result.output
        assert "--account" in result.output
        assert "--user" in result.output
        assert "--password" in result.output
        assert "--warehouse" in result.output
        assert "--role" in result.output

    def test_snowflake_evidence_types_in_help(self):
        """Test evidence types are documented in help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "snowflake", "--help"])
        assert result.exit_code == 0
        assert "users" in result.output
        assert "roles" in result.output
        assert "warehouses" in result.output
        assert "databases" in result.output
        assert "access_history" in result.output
        assert "query_history" in result.output
        assert "grants" in result.output
        assert "network_policies" in result.output

    def test_snowflake_missing_credentials(self):
        """Test error when credentials are missing."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "snowflake"])
        assert result.exit_code == 0
        assert "Error" in result.output
        assert "account" in result.output.lower()

    def test_snowflake_missing_user(self):
        """Test error when user is missing."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "snowflake", "--account", "xy12345"])
        assert result.exit_code == 0
        assert "Error" in result.output
        assert "user" in result.output.lower()

    def test_snowflake_missing_auth(self):
        """Test error when password and private key are missing."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "snowflake", "--account", "xy12345", "--user", "admin"])
        assert result.exit_code == 0
        assert "Error" in result.output
        assert "password" in result.output.lower() or "key" in result.output.lower()

    def test_collect_list_shows_snowflake(self):
        """Test collect list shows snowflake as available."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])
        assert result.exit_code == 0
        assert "snowflake" in result.output
        assert "Available" in result.output


# =============================================================================
# Connection Management Tests
# =============================================================================


class TestConnectionManagement:
    """Tests for connection management."""

    def test_close_connection(self, mock_config):
        """Test closing connection."""
        collector = SnowflakeCollector(config=mock_config)
        mock_conn = MagicMock()
        collector._connection = mock_conn

        collector._close_connection()

        mock_conn.close.assert_called_once()
        assert collector._connection is None

    def test_close_connection_no_connection(self, mock_config):
        """Test closing when no connection exists."""
        collector = SnowflakeCollector(config=mock_config)
        collector._connection = None

        # Should not raise
        collector._close_connection()
        assert collector._connection is None

    def test_close_connection_error(self, mock_config):
        """Test closing connection when close fails."""
        collector = SnowflakeCollector(config=mock_config)
        mock_conn = MagicMock()
        mock_conn.close.side_effect = Exception("Close failed")
        collector._connection = mock_conn

        # Should not raise, just set to None
        collector._close_connection()
        assert collector._connection is None


# =============================================================================
# Import Tests
# =============================================================================


class TestImports:
    """Tests for module imports."""

    def test_import_from_platforms(self):
        """Test importing from platforms package."""
        from attestful.collectors.platforms import (
            SnowflakeCollector,
            SnowflakeCollectorConfig,
        )

        assert SnowflakeCollector is not None
        assert SnowflakeCollectorConfig is not None

    def test_snowflake_connector_import_error(self, mock_config):
        """Test handling missing snowflake-connector-python."""
        collector = SnowflakeCollector(config=mock_config)

        with patch.dict("sys.modules", {"snowflake.connector": None}):
            with patch("builtins.__import__", side_effect=ImportError("No module")):
                with pytest.raises(ImportError) as exc_info:
                    collector._get_connection()

                assert "snowflake-connector-python" in str(exc_info.value)
