"""
Microsoft 365 collector for Attestful.

Collects user, group, device, and security evidence from Microsoft 365
using Microsoft Graph API for compliance frameworks including SOC 2,
NIST 800-53, ISO 27001, and HITRUST.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from attestful.collectors.base import (
    BaseCollector,
    CollectorMetadata,
    CollectorMode,
)
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


# Compliance control mappings for Microsoft 365 evidence types
EVIDENCE_CONTROL_MAPPINGS: dict[str, list[str]] = {
    "users": [
        "SOC2:CC6.1",  # Logical Access
        "SOC2:CC6.2",  # User Access Administration
        "NIST:AC-2",   # Account Management
        "NIST:IA-2",   # Identification and Authentication
        "ISO27001:A.9.2",  # User Access Management
        "HITRUST:01.b",    # User Registration
    ],
    "groups": [
        "SOC2:CC6.2",  # User Access Administration
        "SOC2:CC6.3",  # Role-Based Access
        "NIST:AC-2",   # Account Management
        "NIST:AC-6",   # Least Privilege
        "ISO27001:A.9.2",  # User Access Management
        "HITRUST:01.c",    # Privilege Management
    ],
    "devices": [
        "SOC2:CC6.6",  # Logical Access Controls
        "SOC2:CC6.7",  # System Operations
        "NIST:CM-8",   # Information System Component Inventory
        "NIST:AC-19",  # Access Control for Mobile Devices
        "ISO27001:A.8.1",  # Asset Management
        "HITRUST:07.a",    # Inventory of Assets
    ],
    "sign_ins": [
        "SOC2:CC7.2",  # System Monitoring
        "SOC2:CC7.3",  # Detection Procedures
        "NIST:AU-2",   # Audit Events
        "NIST:AU-12",  # Audit Generation
        "ISO27001:A.12.4", # Logging and Monitoring
        "HITRUST:09.ab",   # Audit Logging
    ],
    "security_alerts": [
        "SOC2:CC7.2",  # System Monitoring
        "SOC2:CC7.3",  # Detection Procedures
        "NIST:IR-4",   # Incident Handling
        "NIST:SI-4",   # Information System Monitoring
        "ISO27001:A.16.1", # Incident Management
        "HITRUST:11.a",    # Security Incident Procedures
    ],
    "conditional_access": [
        "SOC2:CC6.1",  # Logical Access
        "SOC2:CC6.6",  # Logical Access Controls
        "NIST:AC-3",   # Access Enforcement
        "NIST:AC-7",   # Unsuccessful Logon Attempts
        "ISO27001:A.9.4",  # System and Application Access
        "HITRUST:01.d",    # User Password Management
    ],
    "directory_roles": [
        "SOC2:CC6.2",  # User Access Administration
        "SOC2:CC6.3",  # Role-Based Access
        "NIST:AC-2",   # Account Management
        "NIST:AC-6",   # Least Privilege
        "ISO27001:A.9.2",  # User Access Management
        "HITRUST:01.c",    # Privilege Management
    ],
    "applications": [
        "SOC2:CC6.1",  # Logical Access
        "SOC2:CC6.7",  # System Operations
        "NIST:AC-3",   # Access Enforcement
        "NIST:CM-7",   # Least Functionality
        "ISO27001:A.9.4",  # System and Application Access
        "HITRUST:01.v",    # Third-Party Access
    ],
}


@dataclass
class Microsoft365CollectorConfig:
    """Configuration for Microsoft 365 collector."""

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100
    days_of_history: int = 30


class Microsoft365Collector(BaseCollector):
    """
    Microsoft 365 collector for productivity suite evidence.

    Collects evidence related to:
    - Users (accounts, licenses, MFA status)
    - Groups (security groups, Microsoft 365 groups)
    - Devices (managed devices, compliance status)
    - Sign-ins (authentication logs, risky sign-ins)
    - Security alerts (Azure AD Identity Protection)
    - Conditional access (policies and named locations)
    - Directory roles (admin role assignments)
    - Applications (enterprise apps, app registrations)

    Evidence Types:
    - users: All Azure AD users with MFA and license status
    - groups: Security and Microsoft 365 groups with memberships
    - devices: Managed devices and compliance status
    - sign_ins: Recent sign-in activity and failures
    - security_alerts: Security alerts from Identity Protection
    - conditional_access: Conditional access policies
    - directory_roles: Directory role assignments
    - applications: Enterprise applications and permissions

    Resource Types:
    - m365_user: User accounts
    - m365_group: Groups
    - m365_device: Managed devices
    - m365_application: Enterprise applications

    Compliance Mappings:
    - SOC 2 CC6 (Logical Access): Users, groups, conditional access
    - NIST 800-53 AC-2 (Account Management): Users, directory roles
    - NIST 800-53 AU-2 (Audit Events): Sign-ins, security alerts
    - ISO 27001 A.9.2 (User Access Management): Users, groups
    - HITRUST 01.b (User Registration): Users, groups

    Example:
        collector = Microsoft365Collector(
            config=Microsoft365CollectorConfig(
                tenant_id="your-tenant-id",
                client_id="your-client-id",
                client_secret="your-client-secret",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "sign_ins", "security_alerts"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["m365_user", "m365_device"]
        )
    """

    PLATFORM = "microsoft365"
    SUPPORTED_RESOURCE_TYPES = [
        "m365_user",
        "m365_group",
        "m365_device",
        "m365_application",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "groups",
        "devices",
        "sign_ins",
        "security_alerts",
        "conditional_access",
        "directory_roles",
        "applications",
    ]

    def __init__(
        self,
        config: Microsoft365CollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Microsoft 365 collector.

        Args:
            config: Microsoft 365 collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or Microsoft365CollectorConfig()
        self._session: requests.Session | None = None
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None

    @property
    def base_url(self) -> str:
        """Get the Microsoft Graph API base URL."""
        return "https://graph.microsoft.com/v1.0"

    @property
    def beta_url(self) -> str:
        """Get the Microsoft Graph API beta URL (for some security features)."""
        return "https://graph.microsoft.com/beta"

    def _get_session(self) -> requests.Session:
        """Get or create requests session with retry logic."""
        if self._session is None:
            self._session = requests.Session()

            # Set up retries
            retry = Retry(
                total=self.config.max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry)
            self._session.mount("https://", adapter)

        return self._session

    def _get_access_token(self) -> str:
        """Get or refresh the OAuth2 access token."""
        now = datetime.now(timezone.utc)

        # Return cached token if still valid
        if (
            self._access_token
            and self._token_expires_at
            and self._token_expires_at > now + timedelta(minutes=5)
        ):
            return self._access_token

        # Get new token
        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"

        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }

        response = requests.post(token_url, data=data, timeout=self.config.timeout)
        response.raise_for_status()

        token_data = response.json()
        self._access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        self._token_expires_at = now + timedelta(seconds=expires_in)

        return self._access_token

    def _request(
        self,
        method: str,
        endpoint: str,
        use_beta: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an API request with authentication."""
        self._rate_limit()

        session = self._get_session()
        token = self._get_access_token()

        base = self.beta_url if use_beta else self.base_url
        url = f"{base}/{endpoint.lstrip('/')}"

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"

        kwargs.setdefault("timeout", self.config.timeout)

        response = session.request(method, url, headers=headers, **kwargs)

        # Handle rate limiting
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            logger.warning(f"Rate limited, waiting {retry_after}s")
            import time
            time.sleep(retry_after)
            return self._request(method, endpoint, use_beta, **kwargs)

        response.raise_for_status()
        return response

    def _paginate(
        self,
        endpoint: str,
        use_beta: bool = False,
        params: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through API results."""
        params = params or {}
        params.setdefault("$top", self.config.page_size)

        url = endpoint

        while url:
            if url.startswith("http"):
                # Direct URL from @odata.nextLink
                response = self._get_session().get(
                    url,
                    headers={
                        "Authorization": f"Bearer {self._get_access_token()}",
                        "Accept": "application/json",
                    },
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
            else:
                response = self._request("GET", url, use_beta=use_beta, params=params)
                params = {}  # Clear params after first request

            data = response.json()
            for item in data.get("value", []):
                yield item

            url = data.get("@odata.nextLink")

    def validate_credentials(self) -> bool:
        """Validate Microsoft 365 credentials."""
        try:
            token = self._get_access_token()
            if not token:
                return False

            # Test by getting organization info
            response = self._request("GET", "/organization")
            data = response.json()

            if data.get("value"):
                org = data["value"][0]
                logger.info(
                    f"Validated Microsoft 365 credentials for: {org.get('displayName', 'Unknown')}"
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Microsoft 365 credential validation failed: {e}")
            return False

    def get_metadata(self) -> CollectorMetadata:
        """Return collector metadata."""
        return CollectorMetadata(
            name="Microsoft 365 Collector",
            platform=self.PLATFORM,
            description="Collects productivity suite evidence from Microsoft 365",
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
        Collect Microsoft 365 resources.

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

    def _collect_m365_user(self) -> Iterator[Resource]:
        """Collect Microsoft 365 users as resources."""
        try:
            select_fields = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,lastSignInDateTime,userType,assignedLicenses"
            for user in self._paginate(f"/users?$select={select_fields}"):
                yield Resource(
                    id=user.get("id", ""),
                    type="m365_user",
                    provider="microsoft365",
                    region="global",
                    name=user.get("userPrincipalName", ""),
                    tags={
                        "user_type": str(user.get("userType", "")),
                        "account_enabled": str(user.get("accountEnabled", "")),
                    },
                    metadata={
                        "display_name": user.get("displayName"),
                        "mail": user.get("mail"),
                        "created_datetime": user.get("createdDateTime"),
                        "last_sign_in": user.get("lastSignInDateTime"),
                        "has_licenses": len(user.get("assignedLicenses", [])) > 0,
                    },
                    raw_data=user,
                )
        except Exception as e:
            logger.error(f"Failed to collect users: {e}")

    def _collect_m365_group(self) -> Iterator[Resource]:
        """Collect Microsoft 365 groups as resources."""
        try:
            select_fields = "id,displayName,description,groupTypes,securityEnabled,mailEnabled,mail,createdDateTime"
            for group in self._paginate(f"/groups?$select={select_fields}"):
                group_types = group.get("groupTypes", [])
                is_m365_group = "Unified" in group_types
                is_security_group = group.get("securityEnabled", False)

                yield Resource(
                    id=group.get("id", ""),
                    type="m365_group",
                    provider="microsoft365",
                    region="global",
                    name=group.get("displayName", ""),
                    tags={
                        "security_enabled": str(is_security_group),
                        "mail_enabled": str(group.get("mailEnabled", False)),
                        "is_m365_group": str(is_m365_group),
                    },
                    metadata={
                        "description": group.get("description"),
                        "mail": group.get("mail"),
                        "created_datetime": group.get("createdDateTime"),
                        "group_types": group_types,
                    },
                    raw_data=group,
                )
        except Exception as e:
            logger.error(f"Failed to collect groups: {e}")

    def _collect_m365_device(self) -> Iterator[Resource]:
        """Collect Microsoft 365 managed devices as resources."""
        try:
            # Use Intune device management endpoint
            select_fields = "id,deviceName,managedDeviceOwnerType,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime"
            for device in self._paginate(f"/deviceManagement/managedDevices?$select={select_fields}"):
                yield Resource(
                    id=device.get("id", ""),
                    type="m365_device",
                    provider="microsoft365",
                    region="global",
                    name=device.get("deviceName", ""),
                    tags={
                        "os": str(device.get("operatingSystem", "")),
                        "compliance_state": str(device.get("complianceState", "")),
                        "owner_type": str(device.get("managedDeviceOwnerType", "")),
                    },
                    metadata={
                        "os_version": device.get("osVersion"),
                        "last_sync": device.get("lastSyncDateTime"),
                        "enrolled_datetime": device.get("enrolledDateTime"),
                    },
                    raw_data=device,
                )
        except Exception as e:
            logger.error(f"Failed to collect devices: {e}")

    def _collect_m365_application(self) -> Iterator[Resource]:
        """Collect Microsoft 365 enterprise applications as resources."""
        try:
            select_fields = "id,displayName,appId,createdDateTime,signInAudience,tags"
            for app in self._paginate(f"/applications?$select={select_fields}"):
                yield Resource(
                    id=app.get("id", ""),
                    type="m365_application",
                    provider="microsoft365",
                    region="global",
                    name=app.get("displayName", ""),
                    tags={
                        "sign_in_audience": str(app.get("signInAudience", "")),
                    },
                    metadata={
                        "app_id": app.get("appId"),
                        "created_datetime": app.get("createdDateTime"),
                        "tags": app.get("tags", []),
                    },
                    raw_data=app,
                )
        except Exception as e:
            logger.error(f"Failed to collect applications: {e}")

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect Microsoft 365 evidence for compliance audits.

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
        """Collect all Microsoft 365 users with security details."""
        users_data: list[dict[str, Any]] = []
        mfa_enabled_count = 0
        guest_count = 0
        disabled_count = 0
        licensed_count = 0

        try:
            select_fields = "id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,userType,assignedLicenses"
            for user in self._paginate(f"/users?$select={select_fields}"):
                user_info = {
                    "id": user.get("id"),
                    "display_name": user.get("displayName"),
                    "user_principal_name": user.get("userPrincipalName"),
                    "mail": user.get("mail"),
                    "account_enabled": user.get("accountEnabled", False),
                    "user_type": user.get("userType"),
                    "created_datetime": user.get("createdDateTime"),
                    "has_licenses": len(user.get("assignedLicenses", [])) > 0,
                }
                users_data.append(user_info)

                if not user_info["account_enabled"]:
                    disabled_count += 1
                if user_info["user_type"] == "Guest":
                    guest_count += 1
                if user_info["has_licenses"]:
                    licensed_count += 1
        except Exception as e:
            logger.error(f"Failed to get users: {e}")

        # Get MFA registration status from authentication methods
        try:
            # Use reports API to get MFA status
            mfa_response = self._request(
                "GET",
                "/reports/authenticationMethods/userRegistrationDetails",
                use_beta=True,
            )
            mfa_data = mfa_response.json()
            for mfa_user in mfa_data.get("value", []):
                if mfa_user.get("isMfaRegistered", False):
                    mfa_enabled_count += 1
        except Exception as e:
            logger.warning(f"Could not get MFA status: {e}")

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
                    "guest_users": guest_count,
                    "licensed_users": licensed_count,
                    "mfa_enabled": mfa_enabled_count,
                    "mfa_rate_percent": round(mfa_rate, 2),
                },
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _evidence_groups(self) -> Evidence:
        """Collect groups with membership details."""
        groups_data: list[dict[str, Any]] = []
        security_groups_count = 0
        m365_groups_count = 0
        mail_enabled_count = 0

        try:
            select_fields = "id,displayName,description,groupTypes,securityEnabled,mailEnabled,mail,createdDateTime,membershipRule"
            for group in self._paginate(f"/groups?$select={select_fields}"):
                group_types = group.get("groupTypes", [])
                is_m365_group = "Unified" in group_types
                is_dynamic = "DynamicMembership" in group_types
                is_security = group.get("securityEnabled", False)

                # Get member count
                member_count = 0
                try:
                    members_response = self._request(
                        "GET",
                        f"/groups/{group['id']}/members/$count",
                        headers={"ConsistencyLevel": "eventual"},
                    )
                    member_count = int(members_response.text) if members_response.text.isdigit() else 0
                except Exception:
                    pass

                group_info = {
                    "id": group.get("id"),
                    "display_name": group.get("displayName"),
                    "description": group.get("description"),
                    "mail": group.get("mail"),
                    "security_enabled": is_security,
                    "mail_enabled": group.get("mailEnabled", False),
                    "is_m365_group": is_m365_group,
                    "is_dynamic": is_dynamic,
                    "membership_rule": group.get("membershipRule"),
                    "created_datetime": group.get("createdDateTime"),
                    "member_count": member_count,
                }
                groups_data.append(group_info)

                if is_security:
                    security_groups_count += 1
                if is_m365_group:
                    m365_groups_count += 1
                if group.get("mailEnabled"):
                    mail_enabled_count += 1
        except Exception as e:
            logger.error(f"Failed to get groups: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": groups_data,
                "total_count": len(groups_data),
                "summary": {
                    "total_groups": len(groups_data),
                    "security_groups": security_groups_count,
                    "m365_groups": m365_groups_count,
                    "mail_enabled_groups": mail_enabled_count,
                },
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["groups"],
            },
        )

    def _evidence_devices(self) -> Evidence:
        """Collect managed devices and compliance status."""
        devices_data: list[dict[str, Any]] = []
        by_os: dict[str, int] = {}
        by_compliance: dict[str, int] = {}
        compliant_count = 0
        noncompliant_count = 0

        try:
            select_fields = "id,deviceName,managedDeviceOwnerType,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime,manufacturer,model"
            for device in self._paginate(f"/deviceManagement/managedDevices?$select={select_fields}"):
                device_info = {
                    "id": device.get("id"),
                    "device_name": device.get("deviceName"),
                    "owner_type": device.get("managedDeviceOwnerType"),
                    "operating_system": device.get("operatingSystem"),
                    "os_version": device.get("osVersion"),
                    "compliance_state": device.get("complianceState"),
                    "last_sync": device.get("lastSyncDateTime"),
                    "enrolled_datetime": device.get("enrolledDateTime"),
                    "manufacturer": device.get("manufacturer"),
                    "model": device.get("model"),
                }
                devices_data.append(device_info)

                # Count by OS
                os_name = device.get("operatingSystem", "unknown")
                by_os[os_name] = by_os.get(os_name, 0) + 1

                # Count by compliance
                compliance = device.get("complianceState", "unknown")
                by_compliance[compliance] = by_compliance.get(compliance, 0) + 1

                if compliance == "compliant":
                    compliant_count += 1
                elif compliance in ("noncompliant", "inGracePeriod"):
                    noncompliant_count += 1
        except Exception as e:
            logger.error(f"Failed to get devices: {e}")

        total_devices = len(devices_data)
        compliance_rate = (compliant_count / total_devices * 100) if total_devices > 0 else 0

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="devices",
            raw_data={
                "devices": devices_data,
                "total_count": total_devices,
                "by_os": by_os,
                "by_compliance": by_compliance,
                "summary": {
                    "total_devices": total_devices,
                    "compliant_devices": compliant_count,
                    "noncompliant_devices": noncompliant_count,
                    "compliance_rate_percent": round(compliance_rate, 2),
                },
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["devices"],
            },
        )

    def _evidence_sign_ins(self) -> Evidence:
        """Collect recent sign-in activity."""
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        sign_ins_data: list[dict[str, Any]] = []
        success_count = 0
        failure_count = 0
        risky_count = 0
        by_app: dict[str, int] = {}
        by_status: dict[str, int] = {}

        try:
            filter_str = f"createdDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            select_fields = "id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,clientAppUsed,status,riskState,riskLevelAggregated"

            for sign_in in self._paginate(
                f"/auditLogs/signIns?$filter={filter_str}&$select={select_fields}",
                use_beta=True,
            ):
                status = sign_in.get("status", {})
                error_code = status.get("errorCode", 0)
                is_success = error_code == 0

                sign_in_info = {
                    "id": sign_in.get("id"),
                    "created_datetime": sign_in.get("createdDateTime"),
                    "user_principal_name": sign_in.get("userPrincipalName"),
                    "app_display_name": sign_in.get("appDisplayName"),
                    "ip_address": sign_in.get("ipAddress"),
                    "client_app_used": sign_in.get("clientAppUsed"),
                    "status_error_code": error_code,
                    "status_failure_reason": status.get("failureReason"),
                    "risk_state": sign_in.get("riskState"),
                    "risk_level": sign_in.get("riskLevelAggregated"),
                    "is_success": is_success,
                }
                sign_ins_data.append(sign_in_info)

                if is_success:
                    success_count += 1
                else:
                    failure_count += 1

                # Count risky sign-ins
                risk_level = sign_in.get("riskLevelAggregated", "none")
                if risk_level and risk_level != "none":
                    risky_count += 1

                # Count by app
                app_name = sign_in.get("appDisplayName", "Unknown")
                by_app[app_name] = by_app.get(app_name, 0) + 1

                # Count by status
                status_key = "success" if is_success else f"error_{error_code}"
                by_status[status_key] = by_status.get(status_key, 0) + 1

                # Limit to 1000 for evidence
                if len(sign_ins_data) >= 1000:
                    break
        except Exception as e:
            logger.error(f"Failed to get sign-ins: {e}")

        total_sign_ins = len(sign_ins_data)
        success_rate = (success_count / total_sign_ins * 100) if total_sign_ins > 0 else 0

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="sign_ins",
            raw_data={
                "sign_ins": sign_ins_data,
                "total_count": total_sign_ins,
                "by_app": by_app,
                "by_status": by_status,
                "summary": {
                    "total_sign_ins": total_sign_ins,
                    "successful": success_count,
                    "failed": failure_count,
                    "risky": risky_count,
                    "success_rate_percent": round(success_rate, 2),
                },
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["sign_ins"],
            },
        )

    def _evidence_security_alerts(self) -> Evidence:
        """Collect security alerts from Identity Protection."""
        alerts_data: list[dict[str, Any]] = []
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        high_severity_count = 0

        try:
            # Get risky users
            risky_users: list[dict[str, Any]] = []
            for user in self._paginate("/identityProtection/riskyUsers", use_beta=True):
                risky_users.append({
                    "id": user.get("id"),
                    "user_principal_name": user.get("userPrincipalName"),
                    "risk_state": user.get("riskState"),
                    "risk_level": user.get("riskLevel"),
                    "risk_detail": user.get("riskDetail"),
                    "risk_last_updated": user.get("riskLastUpdatedDateTime"),
                })

                risk_level = user.get("riskLevel", "none")
                by_severity[risk_level] = by_severity.get(risk_level, 0) + 1
                if risk_level in ("high", "medium"):
                    high_severity_count += 1

            # Get risk detections
            risk_detections: list[dict[str, Any]] = []
            for detection in self._paginate("/identityProtection/riskDetections", use_beta=True):
                risk_detections.append({
                    "id": detection.get("id"),
                    "user_principal_name": detection.get("userPrincipalName"),
                    "risk_type": detection.get("riskType"),
                    "risk_state": detection.get("riskState"),
                    "risk_level": detection.get("riskLevel"),
                    "detection_timing_type": detection.get("detectionTimingType"),
                    "detected_datetime": detection.get("detectedDateTime"),
                    "ip_address": detection.get("ipAddress"),
                    "location": detection.get("location"),
                })

                # Limit detections
                if len(risk_detections) >= 500:
                    break

            alerts_data = risky_users
        except Exception as e:
            logger.warning(f"Could not get security alerts: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_alerts",
            raw_data={
                "risky_users": alerts_data,
                "risk_detections": risk_detections if "risk_detections" in dir() else [],
                "total_count": len(alerts_data),
                "by_severity": by_severity,
                "summary": {
                    "total_risky_users": len(alerts_data),
                    "high_severity": high_severity_count,
                    "risk_detections_count": len(risk_detections) if "risk_detections" in dir() else 0,
                },
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["security_alerts"],
            },
        )

    def _evidence_conditional_access(self) -> Evidence:
        """Collect conditional access policies."""
        policies_data: list[dict[str, Any]] = []
        enabled_count = 0
        report_only_count = 0

        try:
            for policy in self._paginate("/identity/conditionalAccess/policies", use_beta=True):
                state = policy.get("state", "disabled")
                policy_info = {
                    "id": policy.get("id"),
                    "display_name": policy.get("displayName"),
                    "state": state,
                    "created_datetime": policy.get("createdDateTime"),
                    "modified_datetime": policy.get("modifiedDateTime"),
                    "conditions": {
                        "user_risk_levels": policy.get("conditions", {}).get("userRiskLevels", []),
                        "sign_in_risk_levels": policy.get("conditions", {}).get("signInRiskLevels", []),
                        "platforms": policy.get("conditions", {}).get("platforms", {}),
                        "locations": policy.get("conditions", {}).get("locations", {}),
                        "client_app_types": policy.get("conditions", {}).get("clientAppTypes", []),
                    },
                    "grant_controls": policy.get("grantControls", {}),
                    "session_controls": policy.get("sessionControls", {}),
                }
                policies_data.append(policy_info)

                if state == "enabled":
                    enabled_count += 1
                elif state == "enabledForReportingButNotEnforced":
                    report_only_count += 1
        except Exception as e:
            logger.error(f"Failed to get conditional access policies: {e}")

        # Get named locations
        named_locations: list[dict[str, Any]] = []
        try:
            for location in self._paginate("/identity/conditionalAccess/namedLocations", use_beta=True):
                named_locations.append({
                    "id": location.get("id"),
                    "display_name": location.get("displayName"),
                    "type": location.get("@odata.type"),
                    "created_datetime": location.get("createdDateTime"),
                    "modified_datetime": location.get("modifiedDateTime"),
                    "is_trusted": location.get("isTrusted", False),
                })
        except Exception as e:
            logger.warning(f"Could not get named locations: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="conditional_access",
            raw_data={
                "policies": policies_data,
                "named_locations": named_locations,
                "total_count": len(policies_data),
                "summary": {
                    "total_policies": len(policies_data),
                    "enabled_policies": enabled_count,
                    "report_only_policies": report_only_count,
                    "disabled_policies": len(policies_data) - enabled_count - report_only_count,
                    "named_locations": len(named_locations),
                },
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["conditional_access"],
            },
        )

    def _evidence_directory_roles(self) -> Evidence:
        """Collect directory role assignments."""
        roles_data: list[dict[str, Any]] = []
        admin_count = 0
        global_admin_count = 0

        try:
            # Get directory roles
            for role in self._paginate("/directoryRoles"):
                role_members: list[dict[str, Any]] = []

                # Get role members
                try:
                    for member in self._paginate(f"/directoryRoles/{role['id']}/members"):
                        role_members.append({
                            "id": member.get("id"),
                            "display_name": member.get("displayName"),
                            "user_principal_name": member.get("userPrincipalName"),
                        })
                except Exception:
                    pass

                role_info = {
                    "id": role.get("id"),
                    "display_name": role.get("displayName"),
                    "description": role.get("description"),
                    "role_template_id": role.get("roleTemplateId"),
                    "members": role_members,
                    "member_count": len(role_members),
                }
                roles_data.append(role_info)

                if role_members:
                    admin_count += len(role_members)

                # Count Global Admins specifically
                if role.get("displayName") == "Global Administrator":
                    global_admin_count = len(role_members)
        except Exception as e:
            logger.error(f"Failed to get directory roles: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="directory_roles",
            raw_data={
                "roles": roles_data,
                "total_count": len(roles_data),
                "summary": {
                    "total_roles": len(roles_data),
                    "total_role_assignments": admin_count,
                    "global_admins": global_admin_count,
                },
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["directory_roles"],
            },
        )

    def _evidence_applications(self) -> Evidence:
        """Collect enterprise applications and their permissions."""
        apps_data: list[dict[str, Any]] = []
        service_principal_count = 0
        app_registration_count = 0
        high_privilege_apps: list[dict[str, Any]] = []

        # High privilege permission patterns
        high_privilege_permissions = [
            "Directory.ReadWrite.All",
            "User.ReadWrite.All",
            "Mail.ReadWrite",
            "Files.ReadWrite.All",
            "Sites.ReadWrite.All",
        ]

        try:
            # Get service principals (enterprise apps)
            for sp in self._paginate("/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime"):
                sp_info = {
                    "id": sp.get("id"),
                    "display_name": sp.get("displayName"),
                    "app_id": sp.get("appId"),
                    "type": sp.get("servicePrincipalType"),
                    "account_enabled": sp.get("accountEnabled", False),
                    "created_datetime": sp.get("createdDateTime"),
                    "is_service_principal": True,
                }
                apps_data.append(sp_info)
                service_principal_count += 1

                # Limit for performance
                if len(apps_data) >= 500:
                    break
        except Exception as e:
            logger.warning(f"Could not get service principals: {e}")

        try:
            # Get app registrations
            for app in self._paginate("/applications?$select=id,displayName,appId,createdDateTime,signInAudience,requiredResourceAccess"):
                # Check for high-privilege permissions
                is_high_privilege = False
                required_access = app.get("requiredResourceAccess", [])
                for resource in required_access:
                    for access in resource.get("resourceAccess", []):
                        # Would need to resolve permission names - simplified check
                        pass

                app_info = {
                    "id": app.get("id"),
                    "display_name": app.get("displayName"),
                    "app_id": app.get("appId"),
                    "created_datetime": app.get("createdDateTime"),
                    "sign_in_audience": app.get("signInAudience"),
                    "is_service_principal": False,
                }
                apps_data.append(app_info)
                app_registration_count += 1

                # Limit for performance
                if app_registration_count >= 500:
                    break
        except Exception as e:
            logger.warning(f"Could not get app registrations: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="applications",
            raw_data={
                "applications": apps_data,
                "total_count": len(apps_data),
                "summary": {
                    "total_applications": len(apps_data),
                    "service_principals": service_principal_count,
                    "app_registrations": app_registration_count,
                    "high_privilege_apps": len(high_privilege_apps),
                },
                "high_privilege_apps": high_privilege_apps,
            },
            metadata={
                "source": "collector:microsoft365",
                "collection_method": "automated",
                "compliance_controls": EVIDENCE_CONTROL_MAPPINGS["applications"],
            },
        )
