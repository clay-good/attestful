"""
Snowflake collector for Attestful.

Collects data warehouse evidence from Snowflake
for compliance frameworks including SOC 2, NIST 800-53, ISO 27001, and HITRUST.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Iterator

from attestful.collectors.base import (
    BaseCollector,
    CollectorMetadata,
    CollectorMode,
)
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


# Compliance control mappings for Snowflake evidence types
EVIDENCE_CONTROL_MAPPINGS: dict[str, list[str]] = {
    "users": [
        "SOC2:CC6.1",  # Logical Access
        "SOC2:CC6.2",  # User Access Administration
        "NIST:AC-2",   # Account Management
        "NIST:IA-2",   # Identification and Authentication
        "ISO27001:A.9.2",  # User Access Management
        "HITRUST:01.b",    # User Registration
    ],
    "roles": [
        "SOC2:CC6.2",  # User Access Administration
        "SOC2:CC6.3",  # Role-Based Access
        "NIST:AC-2",   # Account Management
        "NIST:AC-3",   # Access Enforcement
        "ISO27001:A.9.2",  # User Access Management
        "HITRUST:01.c",    # Privilege Management
    ],
    "warehouses": [
        "SOC2:CC6.7",  # System Operations
        "NIST:CP-9",   # Information System Backup
        "NIST:SC-8",   # Transmission Confidentiality
        "ISO27001:A.12.1", # Operational Procedures
        "HITRUST:09.aa",   # Monitoring System Use
    ],
    "databases": [
        "SOC2:CC6.1",  # Logical Access
        "NIST:AC-3",   # Access Enforcement
        "NIST:SC-28",  # Protection of Information at Rest
        "ISO27001:A.8.2",  # Classification of Information
        "HITRUST:06.d",    # Data Protection
    ],
    "access_history": [
        "SOC2:CC7.2",  # System Monitoring
        "SOC2:CC7.3",  # Detection Procedures
        "NIST:AU-2",   # Audit Events
        "NIST:AU-12",  # Audit Generation
        "ISO27001:A.12.4", # Logging and Monitoring
        "HITRUST:09.ab",   # Audit Logging
    ],
    "query_history": [
        "SOC2:CC7.2",  # System Monitoring
        "NIST:AU-2",   # Audit Events
        "NIST:AU-12",  # Audit Generation
        "ISO27001:A.12.4", # Logging and Monitoring
        "HITRUST:09.ab",   # Audit Logging
    ],
    "grants": [
        "SOC2:CC6.3",  # Role-Based Access
        "NIST:AC-3",   # Access Enforcement
        "NIST:AC-6",   # Least Privilege
        "ISO27001:A.9.4",  # System and Application Access
        "HITRUST:01.c",    # Privilege Management
    ],
    "network_policies": [
        "SOC2:CC6.6",  # Logical Access Controls
        "NIST:SC-7",   # Boundary Protection
        "NIST:AC-17",  # Remote Access
        "ISO27001:A.13.1", # Network Security
        "HITRUST:01.n",    # Network Segregation
    ],
}


@dataclass
class SnowflakeCollectorConfig:
    """Configuration for Snowflake collector."""

    account: str = ""  # account identifier (e.g., xy12345.us-east-1)
    user: str = ""
    password: str = ""
    warehouse: str = ""  # optional default warehouse
    database: str = ""   # optional default database
    role: str = ""       # optional role to use
    private_key_path: str = ""  # for key-pair auth
    private_key_passphrase: str = ""
    timeout: int = 60
    days_of_history: int = 30
    query_limit: int = 1000


class SnowflakeCollector(BaseCollector):
    """
    Snowflake collector for data warehouse evidence.

    Collects evidence related to:
    - Users (accounts, roles, authentication)
    - Roles (role hierarchy, grants)
    - Warehouses (compute resources, configuration)
    - Databases (schemas, tables, access)
    - Access history (login attempts, sessions)
    - Query history (queries, performance)
    - Grants (privilege assignments)
    - Network policies (IP restrictions)

    Evidence Types:
    - users: All Snowflake users with MFA status and role assignments
    - roles: Role definitions and hierarchy
    - warehouses: Warehouse configurations and resource usage
    - databases: Database inventory and ownership
    - access_history: Login history and session data
    - query_history: Recent query activity
    - grants: Privilege grants across objects
    - network_policies: Network access restrictions

    Resource Types:
    - snowflake_user: User accounts
    - snowflake_role: Roles
    - snowflake_warehouse: Compute warehouses
    - snowflake_database: Databases

    Compliance Mappings:
    - SOC 2 CC6 (Logical Access): Users, roles, grants
    - NIST 800-53 AC-2 (Account Management): Users, access history
    - NIST 800-53 AU-2 (Audit Events): Query history, access history
    - ISO 27001 A.9.2 (User Access Management): Users, roles
    - HITRUST 01.b (User Registration): Users, roles

    Example:
        collector = SnowflakeCollector(
            config=SnowflakeCollectorConfig(
                account="xy12345.us-east-1",
                user="admin",
                password="secure_password",
                warehouse="COMPUTE_WH",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "roles", "access_history"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["snowflake_user", "snowflake_warehouse"]
        )
    """

    PLATFORM = "snowflake"
    SUPPORTED_RESOURCE_TYPES = [
        "snowflake_user",
        "snowflake_role",
        "snowflake_warehouse",
        "snowflake_database",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "roles",
        "warehouses",
        "databases",
        "access_history",
        "query_history",
        "grants",
        "network_policies",
    ]

    def __init__(
        self,
        config: SnowflakeCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Snowflake collector.

        Args:
            config: Snowflake collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or SnowflakeCollectorConfig()
        self._connection: Any = None

    def _get_connection(self) -> Any:
        """Get or create Snowflake connection."""
        if self._connection is not None:
            return self._connection

        try:
            import snowflake.connector
        except ImportError:
            raise ImportError(
                "snowflake-connector-python is required for Snowflake collection. "
                "Install it with: pip install 'attestful[snowflake]'"
            )

        connect_args: dict[str, Any] = {
            "account": self.config.account,
            "user": self.config.user,
            "login_timeout": self.config.timeout,
            "network_timeout": self.config.timeout,
        }

        # Password authentication
        if self.config.password:
            connect_args["password"] = self.config.password

        # Key-pair authentication
        if self.config.private_key_path:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization

            with open(self.config.private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=self.config.private_key_passphrase.encode()
                    if self.config.private_key_passphrase
                    else None,
                    backend=default_backend(),
                )
            connect_args["private_key"] = private_key

        # Optional defaults
        if self.config.warehouse:
            connect_args["warehouse"] = self.config.warehouse
        if self.config.database:
            connect_args["database"] = self.config.database
        if self.config.role:
            connect_args["role"] = self.config.role

        self._connection = snowflake.connector.connect(**connect_args)
        return self._connection

    def _execute_query(
        self,
        query: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a SQL query and return results as list of dicts."""
        self._rate_limit()

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            columns = [desc[0].lower() for desc in cursor.description]
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            return results
        finally:
            cursor.close()

    def _close_connection(self) -> None:
        """Close the Snowflake connection."""
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None

    def validate_credentials(self) -> bool:
        """Validate Snowflake credentials."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_ACCOUNT()")
            result = cursor.fetchone()
            cursor.close()

            if result:
                logger.info(
                    f"Validated Snowflake credentials: user={result[0]}, "
                    f"role={result[1]}, account={result[2]}"
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Snowflake credential validation failed: {e}")
            return False

    def get_metadata(self) -> CollectorMetadata:
        """Return collector metadata."""
        return CollectorMetadata(
            name="Snowflake Collector",
            platform=self.PLATFORM,
            description="Collects data warehouse evidence from Snowflake",
            mode=CollectorMode.BOTH,
            resource_types=self.SUPPORTED_RESOURCE_TYPES,
            evidence_types=self.SUPPORTED_EVIDENCE_TYPES,
            version="1.0.0",
        )

    # =========================================================================
    # Resource Collection Methods
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """
        Collect Snowflake resources.

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

    def _collect_snowflake_user(self) -> Iterator[Resource]:
        """Collect Snowflake users as resources."""
        try:
            users = self._execute_query("SHOW USERS")

            for user in users:
                user_name = user.get("name", "")
                yield Resource(
                    id=user_name,
                    type="snowflake_user",
                    provider="snowflake",
                    region=self.config.account,
                    name=user_name,
                    tags={
                        "login_name": str(user.get("login_name", "")),
                        "disabled": str(user.get("disabled", "")),
                        "locked": str(user.get("locked", "")),
                        "default_role": str(user.get("default_role", "")),
                    },
                    metadata={
                        "display_name": user.get("display_name"),
                        "email": user.get("email"),
                        "created_on": str(user.get("created_on", "")),
                        "last_success_login": str(user.get("last_success_login", "")),
                        "ext_authn_duo": user.get("ext_authn_duo"),
                        "has_mfa": user.get("has_mfa", False),
                        "has_password": user.get("has_password"),
                        "has_rsa_public_key": user.get("has_rsa_public_key"),
                    },
                    raw_data=user,
                )
        except Exception as e:
            logger.error(f"Failed to collect users: {e}")

    def _collect_snowflake_role(self) -> Iterator[Resource]:
        """Collect Snowflake roles as resources."""
        try:
            roles = self._execute_query("SHOW ROLES")

            for role in roles:
                role_name = role.get("name", "")
                yield Resource(
                    id=role_name,
                    type="snowflake_role",
                    provider="snowflake",
                    region=self.config.account,
                    name=role_name,
                    tags={
                        "is_default": str(role.get("is_default", "")),
                        "is_current": str(role.get("is_current", "")),
                        "is_inherited": str(role.get("is_inherited", "")),
                    },
                    metadata={
                        "comment": role.get("comment"),
                        "created_on": str(role.get("created_on", "")),
                        "owner": role.get("owner"),
                        "assigned_to_users": role.get("assigned_to_users", 0),
                        "granted_to_roles": role.get("granted_to_roles", 0),
                        "granted_roles": role.get("granted_roles", 0),
                    },
                    raw_data=role,
                )
        except Exception as e:
            logger.error(f"Failed to collect roles: {e}")

    def _collect_snowflake_warehouse(self) -> Iterator[Resource]:
        """Collect Snowflake warehouses as resources."""
        try:
            warehouses = self._execute_query("SHOW WAREHOUSES")

            for wh in warehouses:
                wh_name = wh.get("name", "")
                yield Resource(
                    id=wh_name,
                    type="snowflake_warehouse",
                    provider="snowflake",
                    region=self.config.account,
                    name=wh_name,
                    tags={
                        "state": str(wh.get("state", "")),
                        "size": str(wh.get("size", "")),
                        "type": str(wh.get("type", "")),
                    },
                    metadata={
                        "created_on": str(wh.get("created_on", "")),
                        "auto_suspend": wh.get("auto_suspend"),
                        "auto_resume": wh.get("auto_resume"),
                        "available": wh.get("available"),
                        "provisioning": wh.get("provisioning"),
                        "running": wh.get("running"),
                        "queued": wh.get("queued"),
                        "min_cluster_count": wh.get("min_cluster_count"),
                        "max_cluster_count": wh.get("max_cluster_count"),
                        "scaling_policy": wh.get("scaling_policy"),
                        "owner": wh.get("owner"),
                        "comment": wh.get("comment"),
                        "resource_monitor": wh.get("resource_monitor"),
                    },
                    raw_data=wh,
                )
        except Exception as e:
            logger.error(f"Failed to collect warehouses: {e}")

    def _collect_snowflake_database(self) -> Iterator[Resource]:
        """Collect Snowflake databases as resources."""
        try:
            databases = self._execute_query("SHOW DATABASES")

            for db in databases:
                db_name = db.get("name", "")
                yield Resource(
                    id=db_name,
                    type="snowflake_database",
                    provider="snowflake",
                    region=self.config.account,
                    name=db_name,
                    tags={
                        "is_default": str(db.get("is_default", "")),
                        "is_current": str(db.get("is_current", "")),
                        "origin": str(db.get("origin", "")),
                    },
                    metadata={
                        "created_on": str(db.get("created_on", "")),
                        "owner": db.get("owner"),
                        "comment": db.get("comment"),
                        "options": db.get("options"),
                        "retention_time": db.get("retention_time"),
                        "transient": db.get("transient"),
                    },
                    raw_data=db,
                )
        except Exception as e:
            logger.error(f"Failed to collect databases: {e}")

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect Snowflake evidence for compliance audits.

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

        result = CollectionResult(
            platform=self.PLATFORM,
            evidence_items=evidence_items,
            errors=errors,
        )
        result.complete()
        return result

    def _evidence_users(self) -> Evidence:
        """Collect all Snowflake users with security details."""
        try:
            users = self._execute_query("SHOW USERS")
        except Exception as e:
            logger.error(f"Failed to get users: {e}")
            users = []

        # Process users
        users_data: list[dict[str, Any]] = []
        mfa_enabled_count = 0
        disabled_count = 0
        locked_count = 0
        service_accounts: list[dict[str, Any]] = []

        for user in users:
            user_info = {
                "name": user.get("name"),
                "login_name": user.get("login_name"),
                "display_name": user.get("display_name"),
                "email": user.get("email"),
                "disabled": user.get("disabled") == "true",
                "locked": user.get("locked") == "true",
                "default_role": user.get("default_role"),
                "default_warehouse": user.get("default_warehouse"),
                "created_on": str(user.get("created_on", "")),
                "last_success_login": str(user.get("last_success_login", "")),
                "ext_authn_duo": user.get("ext_authn_duo") == "true",
                "has_mfa": user.get("has_mfa") == "true" or user.get("ext_authn_duo") == "true",
                "has_password": user.get("has_password") == "true",
                "has_rsa_public_key": user.get("has_rsa_public_key") == "true",
                "comment": user.get("comment"),
            }
            users_data.append(user_info)

            if user_info["has_mfa"]:
                mfa_enabled_count += 1
            if user_info["disabled"]:
                disabled_count += 1
            if user_info["locked"]:
                locked_count += 1

            # Identify potential service accounts (no email or specific naming)
            if not user_info.get("email") or any(
                kw in str(user_info.get("name", "")).lower()
                for kw in ["svc", "service", "bot", "etl", "pipeline", "sys"]
            ):
                service_accounts.append(user_info)

        total_users = len(users_data)
        active_users = total_users - disabled_count
        mfa_rate = (mfa_enabled_count / active_users * 100) if active_users > 0 else 0

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users_data,
                "total_count": total_users,
                "summary": {
                    "total_users": total_users,
                    "active_users": active_users,
                    "disabled_users": disabled_count,
                    "locked_users": locked_count,
                    "mfa_enabled": mfa_enabled_count,
                    "mfa_rate_percent": round(mfa_rate, 2),
                    "service_accounts": len(service_accounts),
                },
                "service_accounts": service_accounts,
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _evidence_roles(self) -> Evidence:
        """Collect role definitions and hierarchy."""
        try:
            roles = self._execute_query("SHOW ROLES")
        except Exception as e:
            logger.error(f"Failed to get roles: {e}")
            roles = []

        # Process roles
        roles_data: list[dict[str, Any]] = []
        system_roles: list[str] = []
        custom_roles: list[str] = []

        # Known system roles
        system_role_names = {
            "ACCOUNTADMIN", "SECURITYADMIN", "USERADMIN", "SYSADMIN",
            "PUBLIC", "ORGADMIN"
        }

        for role in roles:
            role_name = role.get("name", "")
            role_info = {
                "name": role_name,
                "comment": role.get("comment"),
                "created_on": str(role.get("created_on", "")),
                "owner": role.get("owner"),
                "assigned_to_users": role.get("assigned_to_users", 0),
                "granted_to_roles": role.get("granted_to_roles", 0),
                "granted_roles": role.get("granted_roles", 0),
                "is_default": role.get("is_default") == "true",
                "is_system_role": role_name.upper() in system_role_names,
            }
            roles_data.append(role_info)

            if role_name.upper() in system_role_names:
                system_roles.append(role_name)
            else:
                custom_roles.append(role_name)

        # Get role grants hierarchy
        role_hierarchy: list[dict[str, Any]] = []
        try:
            grants = self._execute_query(
                "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
                "WHERE GRANTED_ON = 'ROLE' AND DELETED_ON IS NULL"
            )
            for grant in grants:
                role_hierarchy.append({
                    "grantee_role": grant.get("grantee_name"),
                    "granted_role": grant.get("name"),
                    "granted_by": grant.get("granted_by"),
                    "created_on": str(grant.get("created_on", "")),
                })
        except Exception as e:
            logger.warning(f"Could not get role hierarchy: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="roles",
            raw_data={
                "roles": roles_data,
                "total_count": len(roles_data),
                "summary": {
                    "total_roles": len(roles_data),
                    "system_roles": len(system_roles),
                    "custom_roles": len(custom_roles),
                },
                "system_roles": system_roles,
                "custom_roles": custom_roles,
                "role_hierarchy": role_hierarchy,
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["roles"],
            },
        )

    def _evidence_warehouses(self) -> Evidence:
        """Collect warehouse configurations and usage."""
        try:
            warehouses = self._execute_query("SHOW WAREHOUSES")
        except Exception as e:
            logger.error(f"Failed to get warehouses: {e}")
            warehouses = []

        # Process warehouses
        wh_data: list[dict[str, Any]] = []
        by_size: dict[str, int] = {}
        by_state: dict[str, int] = {}
        suspended_warehouses: list[str] = []
        running_warehouses: list[str] = []

        for wh in warehouses:
            wh_name = wh.get("name", "")
            wh_info = {
                "name": wh_name,
                "state": wh.get("state"),
                "size": wh.get("size"),
                "type": wh.get("type"),
                "created_on": str(wh.get("created_on", "")),
                "auto_suspend": wh.get("auto_suspend"),
                "auto_resume": wh.get("auto_resume"),
                "min_cluster_count": wh.get("min_cluster_count"),
                "max_cluster_count": wh.get("max_cluster_count"),
                "scaling_policy": wh.get("scaling_policy"),
                "owner": wh.get("owner"),
                "comment": wh.get("comment"),
                "resource_monitor": wh.get("resource_monitor"),
                "running": wh.get("running", 0),
                "queued": wh.get("queued", 0),
            }
            wh_data.append(wh_info)

            # Count by size
            size = wh.get("size", "Unknown")
            by_size[size] = by_size.get(size, 0) + 1

            # Count by state
            state = wh.get("state", "Unknown")
            by_state[state] = by_state.get(state, 0) + 1

            if state == "SUSPENDED":
                suspended_warehouses.append(wh_name)
            elif state in ["STARTED", "RUNNING"]:
                running_warehouses.append(wh_name)

        # Get warehouse usage if available
        usage_data: list[dict[str, Any]] = []
        try:
            since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
            usage = self._execute_query(
                f"""
                SELECT WAREHOUSE_NAME, SUM(CREDITS_USED) as TOTAL_CREDITS,
                       COUNT(*) as USAGE_COUNT
                FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
                WHERE START_TIME >= '{since.strftime("%Y-%m-%d")}'
                GROUP BY WAREHOUSE_NAME
                ORDER BY TOTAL_CREDITS DESC
                """
            )
            usage_data = usage
        except Exception as e:
            logger.warning(f"Could not get warehouse usage: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="warehouses",
            raw_data={
                "warehouses": wh_data,
                "total_count": len(wh_data),
                "by_size": by_size,
                "by_state": by_state,
                "summary": {
                    "total_warehouses": len(wh_data),
                    "running": len(running_warehouses),
                    "suspended": len(suspended_warehouses),
                },
                "running_warehouses": running_warehouses,
                "suspended_warehouses": suspended_warehouses,
                "usage": usage_data,
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["warehouses"],
            },
        )

    def _evidence_databases(self) -> Evidence:
        """Collect database inventory and ownership."""
        try:
            databases = self._execute_query("SHOW DATABASES")
        except Exception as e:
            logger.error(f"Failed to get databases: {e}")
            databases = []

        # Process databases
        db_data: list[dict[str, Any]] = []
        transient_dbs: list[str] = []
        shared_dbs: list[str] = []

        for db in databases:
            db_name = db.get("name", "")
            origin = db.get("origin", "")
            is_transient = db.get("transient") == "true"

            db_info = {
                "name": db_name,
                "created_on": str(db.get("created_on", "")),
                "owner": db.get("owner"),
                "comment": db.get("comment"),
                "options": db.get("options"),
                "retention_time": db.get("retention_time"),
                "transient": is_transient,
                "origin": origin,
                "is_shared": bool(origin),
            }
            db_data.append(db_info)

            if is_transient:
                transient_dbs.append(db_name)
            if origin:
                shared_dbs.append(db_name)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="databases",
            raw_data={
                "databases": db_data,
                "total_count": len(db_data),
                "summary": {
                    "total_databases": len(db_data),
                    "transient_databases": len(transient_dbs),
                    "shared_databases": len(shared_dbs),
                },
                "transient_databases": transient_dbs,
                "shared_databases": shared_dbs,
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["databases"],
            },
        )

    def _evidence_access_history(self) -> Evidence:
        """Collect login history and session data."""
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        # Get login history
        login_data: list[dict[str, Any]] = []
        try:
            logins = self._execute_query(
                f"""
                SELECT USER_NAME, EVENT_TYPE, IS_SUCCESS, CLIENT_IP,
                       REPORTED_CLIENT_TYPE, REPORTED_CLIENT_VERSION,
                       FIRST_AUTHENTICATION_FACTOR, SECOND_AUTHENTICATION_FACTOR,
                       EVENT_TIMESTAMP, ERROR_CODE, ERROR_MESSAGE
                FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
                WHERE EVENT_TIMESTAMP >= '{since.strftime("%Y-%m-%d")}'
                ORDER BY EVENT_TIMESTAMP DESC
                LIMIT {self.config.query_limit}
                """
            )
            for login in logins:
                login_data.append({
                    "user_name": login.get("user_name"),
                    "event_type": login.get("event_type"),
                    "is_success": login.get("is_success") == "YES",
                    "client_ip": login.get("client_ip"),
                    "client_type": login.get("reported_client_type"),
                    "client_version": login.get("reported_client_version"),
                    "first_auth_factor": login.get("first_authentication_factor"),
                    "second_auth_factor": login.get("second_authentication_factor"),
                    "event_timestamp": str(login.get("event_timestamp", "")),
                    "error_code": login.get("error_code"),
                    "error_message": login.get("error_message"),
                })
        except Exception as e:
            logger.warning(f"Could not get login history: {e}")

        # Calculate statistics
        successful_logins = sum(1 for l in login_data if l.get("is_success"))
        failed_logins = len(login_data) - successful_logins
        unique_users = len(set(l.get("user_name") for l in login_data))
        unique_ips = len(set(l.get("client_ip") for l in login_data if l.get("client_ip")))

        # Identify failed login attempts per user
        failed_by_user: dict[str, int] = {}
        for login in login_data:
            if not login.get("is_success"):
                user = login.get("user_name", "unknown")
                failed_by_user[user] = failed_by_user.get(user, 0) + 1

        # Users with high failure rate
        suspicious_users = [
            {"user": user, "failed_attempts": count}
            for user, count in failed_by_user.items()
            if count >= 5
        ]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="access_history",
            raw_data={
                "login_events": login_data,
                "total_events": len(login_data),
                "summary": {
                    "successful_logins": successful_logins,
                    "failed_logins": failed_logins,
                    "unique_users": unique_users,
                    "unique_ips": unique_ips,
                    "success_rate_percent": round(
                        successful_logins / len(login_data) * 100, 2
                    ) if login_data else 0,
                },
                "failed_by_user": failed_by_user,
                "suspicious_users": suspicious_users,
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["access_history"],
            },
        )

    def _evidence_query_history(self) -> Evidence:
        """Collect recent query activity."""
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        query_data: list[dict[str, Any]] = []
        try:
            queries = self._execute_query(
                f"""
                SELECT QUERY_ID, QUERY_TYPE, USER_NAME, ROLE_NAME,
                       DATABASE_NAME, SCHEMA_NAME, WAREHOUSE_NAME,
                       EXECUTION_STATUS, ERROR_CODE, ERROR_MESSAGE,
                       START_TIME, END_TIME, TOTAL_ELAPSED_TIME,
                       BYTES_SCANNED, ROWS_PRODUCED, CREDITS_USED_CLOUD_SERVICES
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
                WHERE START_TIME >= '{since.strftime("%Y-%m-%d")}'
                ORDER BY START_TIME DESC
                LIMIT {self.config.query_limit}
                """
            )
            for query in queries:
                query_data.append({
                    "query_id": query.get("query_id"),
                    "query_type": query.get("query_type"),
                    "user_name": query.get("user_name"),
                    "role_name": query.get("role_name"),
                    "database_name": query.get("database_name"),
                    "schema_name": query.get("schema_name"),
                    "warehouse_name": query.get("warehouse_name"),
                    "execution_status": query.get("execution_status"),
                    "error_code": query.get("error_code"),
                    "error_message": query.get("error_message"),
                    "start_time": str(query.get("start_time", "")),
                    "end_time": str(query.get("end_time", "")),
                    "elapsed_time_ms": query.get("total_elapsed_time"),
                    "bytes_scanned": query.get("bytes_scanned"),
                    "rows_produced": query.get("rows_produced"),
                    "credits_used": query.get("credits_used_cloud_services"),
                })
        except Exception as e:
            logger.warning(f"Could not get query history: {e}")

        # Calculate statistics
        by_user: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        failed_queries: list[dict[str, Any]] = []

        for query in query_data:
            user = query.get("user_name", "unknown")
            by_user[user] = by_user.get(user, 0) + 1

            query_type = query.get("query_type", "unknown")
            by_type[query_type] = by_type.get(query_type, 0) + 1

            status = query.get("execution_status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

            if status == "FAIL":
                failed_queries.append({
                    "query_id": query.get("query_id"),
                    "user": user,
                    "error_code": query.get("error_code"),
                    "error_message": query.get("error_message"),
                })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="query_history",
            raw_data={
                "queries": query_data,
                "total_queries": len(query_data),
                "by_user": by_user,
                "by_type": by_type,
                "by_status": by_status,
                "summary": {
                    "total_queries": len(query_data),
                    "unique_users": len(by_user),
                    "failed_queries": len(failed_queries),
                    "success_rate_percent": round(
                        (len(query_data) - len(failed_queries)) / len(query_data) * 100, 2
                    ) if query_data else 0,
                },
                "failed_queries": failed_queries,
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["query_history"],
            },
        )

    def _evidence_grants(self) -> Evidence:
        """Collect privilege grants across objects."""
        grants_data: list[dict[str, Any]] = []

        # Get grants to roles
        try:
            grants = self._execute_query(
                f"""
                SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA,
                       GRANTEE_NAME, GRANT_OPTION, GRANTED_BY, CREATED_ON
                FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                WHERE DELETED_ON IS NULL
                LIMIT {self.config.query_limit}
                """
            )
            for grant in grants:
                grants_data.append({
                    "privilege": grant.get("privilege"),
                    "granted_on": grant.get("granted_on"),
                    "object_name": grant.get("name"),
                    "database": grant.get("table_catalog"),
                    "schema": grant.get("table_schema"),
                    "grantee": grant.get("grantee_name"),
                    "grantee_type": "ROLE",
                    "grant_option": grant.get("grant_option") == "true",
                    "granted_by": grant.get("granted_by"),
                    "created_on": str(grant.get("created_on", "")),
                })
        except Exception as e:
            logger.warning(f"Could not get grants to roles: {e}")

        # Get grants to users
        try:
            user_grants = self._execute_query(
                f"""
                SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA,
                       GRANTEE_NAME, GRANT_OPTION, GRANTED_BY, CREATED_ON
                FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                WHERE DELETED_ON IS NULL
                LIMIT {self.config.query_limit}
                """
            )
            for grant in user_grants:
                grants_data.append({
                    "privilege": grant.get("privilege"),
                    "granted_on": grant.get("granted_on"),
                    "object_name": grant.get("name"),
                    "database": grant.get("table_catalog"),
                    "schema": grant.get("table_schema"),
                    "grantee": grant.get("grantee_name"),
                    "grantee_type": "USER",
                    "grant_option": grant.get("grant_option") == "true",
                    "granted_by": grant.get("granted_by"),
                    "created_on": str(grant.get("created_on", "")),
                })
        except Exception as e:
            logger.warning(f"Could not get grants to users: {e}")

        # Analyze grants
        by_privilege: dict[str, int] = {}
        by_object_type: dict[str, int] = {}
        privileged_grants: list[dict[str, Any]] = []

        high_privilege_keywords = ["OWNERSHIP", "ALL", "MANAGE", "CONTROL", "ACCOUNTADMIN"]

        for grant in grants_data:
            priv = grant.get("privilege", "unknown")
            by_privilege[priv] = by_privilege.get(priv, 0) + 1

            obj_type = grant.get("granted_on", "unknown")
            by_object_type[obj_type] = by_object_type.get(obj_type, 0) + 1

            # Track high-privilege grants
            if any(kw in priv.upper() for kw in high_privilege_keywords):
                privileged_grants.append(grant)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="grants",
            raw_data={
                "grants": grants_data,
                "total_count": len(grants_data),
                "by_privilege": by_privilege,
                "by_object_type": by_object_type,
                "summary": {
                    "total_grants": len(grants_data),
                    "unique_privileges": len(by_privilege),
                    "high_privilege_grants": len(privileged_grants),
                },
                "high_privilege_grants": privileged_grants,
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["grants"],
            },
        )

    def _evidence_network_policies(self) -> Evidence:
        """Collect network access restrictions."""
        policies_data: list[dict[str, Any]] = []

        try:
            policies = self._execute_query("SHOW NETWORK POLICIES")
            for policy in policies:
                policy_name = policy.get("name", "")
                policy_info = {
                    "name": policy_name,
                    "created_on": str(policy.get("created_on", "")),
                    "comment": policy.get("comment"),
                    "entries_in_allowed_ip_list": policy.get("entries_in_allowed_ip_list", 0),
                    "entries_in_blocked_ip_list": policy.get("entries_in_blocked_ip_list", 0),
                }

                # Get policy details
                try:
                    details = self._execute_query(f"DESCRIBE NETWORK POLICY {policy_name}")
                    allowed_ips = []
                    blocked_ips = []
                    for detail in details:
                        if detail.get("name") == "ALLOWED_IP_LIST":
                            allowed_ips = detail.get("value", "").split(",")
                        elif detail.get("name") == "BLOCKED_IP_LIST":
                            blocked_ips = detail.get("value", "").split(",")
                    policy_info["allowed_ip_list"] = [ip.strip() for ip in allowed_ips if ip.strip()]
                    policy_info["blocked_ip_list"] = [ip.strip() for ip in blocked_ips if ip.strip()]
                except Exception:
                    pass

                policies_data.append(policy_info)
        except Exception as e:
            logger.warning(f"Could not get network policies: {e}")

        # Check if account has network policy
        account_network_policy = None
        try:
            params = self._execute_query(
                "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT"
            )
            for param in params:
                if param.get("key") == "NETWORK_POLICY":
                    account_network_policy = param.get("value")
        except Exception:
            pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="network_policies",
            raw_data={
                "policies": policies_data,
                "total_count": len(policies_data),
                "account_network_policy": account_network_policy,
                "summary": {
                    "total_policies": len(policies_data),
                    "account_policy_enabled": account_network_policy is not None,
                },
            },
            metadata={
                "source": "collector:snowflake",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["network_policies"],
            },
        )
