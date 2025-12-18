"""
Google Workspace collector for productivity suite evidence.

Collects user, group, device, and security evidence from Google Workspace
Admin SDK for compliance and audit documentation.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.models import CollectionResult, Evidence, Resource

logger = logging.getLogger(__name__)


@dataclass
class GoogleWorkspaceCollectorConfig:
    """Configuration for Google Workspace collector."""

    credentials_file: str = ""  # Path to service account JSON
    delegated_user: str = ""  # Admin user to impersonate
    customer_id: str = "my_customer"  # Google Workspace customer ID
    domain: str = ""  # Primary domain
    timeout: int = 30
    page_size: int = 100
    days_of_history: int = 90


class GoogleWorkspaceCollector(BaseCollector):
    """
    Collector for Google Workspace Admin SDK.

    Collects:
    - Users: User accounts, status, MFA, and admin roles
    - Groups: Group memberships and settings
    - Devices: Chrome and mobile devices
    - Security: Login activity and security alerts
    - Org Units: Organizational structure
    - Tokens: OAuth tokens and third-party app access

    Evidence types map to compliance controls for:
    - SOC 2: CC6.1 (Access Controls), CC6.2 (Registration), CC6.3 (Removal)
    - NIST 800-53: AC-2 (Account Management), IA-2 (Identification), AU-2 (Audit Events)
    - ISO 27001: A.9.2.1 (User Registration), A.9.2.2 (User Access), A.9.2.6 (Removal)
    - HITRUST: 01.b (User Registration), 01.c (Privilege Management), 01.q (User ID Management)
    """

    PLATFORM = "google_workspace"
    SUPPORTED_RESOURCE_TYPES = [
        "gws_user",
        "gws_group",
        "gws_device",
        "gws_org_unit",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "groups",
        "devices",
        "login_activity",
        "org_units",
        "tokens",
        "security_alerts",
    ]

    # Map evidence types to compliance framework controls
    EVIDENCE_CONTROL_MAPPINGS = {
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "IA-2", "IA-4", "IA-5"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3", "A.9.2.6"],
            "hitrust": ["01.b", "01.c", "01.q", "01.v"],
        },
        "groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.b", "01.c"],
        },
        "devices": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["CM-8", "AC-19", "MP-7"],
            "iso_27001": ["A.6.2.1", "A.8.1.1", "A.11.2.6"],
            "hitrust": ["07.a", "09.j", "09.m"],
        },
        "login_activity": {
            "soc2": ["CC4.1", "CC6.1", "CC7.2"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AC-7"],
            "iso_27001": ["A.9.4.2", "A.12.4.1", "A.12.4.3"],
            "hitrust": ["01.d", "09.aa", "09.ab"],
        },
        "org_units": {
            "soc2": ["CC5.2", "CC6.1"],
            "nist_800_53": ["AC-2", "PM-10"],
            "iso_27001": ["A.6.1.1", "A.6.1.2"],
            "hitrust": ["01.a", "05.a"],
        },
        "tokens": {
            "soc2": ["CC6.1", "CC6.7"],
            "nist_800_53": ["AC-3", "AC-6", "IA-8"],
            "iso_27001": ["A.9.4.1", "A.9.4.4"],
            "hitrust": ["01.d", "01.v"],
        },
        "security_alerts": {
            "soc2": ["CC4.1", "CC7.2", "CC7.3"],
            "nist_800_53": ["IR-4", "IR-5", "SI-4"],
            "iso_27001": ["A.12.4.1", "A.16.1.2", "A.16.1.4"],
            "hitrust": ["09.ab", "11.a", "11.c"],
        },
    }

    def __init__(self, config: GoogleWorkspaceCollectorConfig | None = None):
        """Initialize Google Workspace collector."""
        self.config = config or GoogleWorkspaceCollectorConfig()
        self._admin_service: Any = None
        self._reports_service: Any = None
        self._alerts_service: Any = None

    @property
    def metadata(self) -> CollectorMetadata:
        """Return collector metadata."""
        return CollectorMetadata(
            name="Google Workspace Collector",
            platform=self.PLATFORM,
            description="Collects productivity suite evidence from Google Workspace",
            mode=CollectorMode.BOTH,
            resource_types=self.SUPPORTED_RESOURCE_TYPES,
            evidence_types=self.SUPPORTED_EVIDENCE_TYPES,
            version="1.0.0",
        )

    def _get_admin_service(self) -> Any:
        """Get or create Admin SDK Directory service."""
        if self._admin_service is None:
            try:
                from google.oauth2 import service_account
                from googleapiclient.discovery import build

                credentials = service_account.Credentials.from_service_account_file(
                    self.config.credentials_file,
                    scopes=[
                        "https://www.googleapis.com/auth/admin.directory.user.readonly",
                        "https://www.googleapis.com/auth/admin.directory.group.readonly",
                        "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
                        "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
                        "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
                    ],
                    subject=self.config.delegated_user,
                )
                self._admin_service = build("admin", "directory_v1", credentials=credentials)
            except ImportError:
                raise ConfigurationError(
                    "Google API client library not installed. "
                    "Install with: pip install google-api-python-client google-auth"
                )
            except Exception as e:
                raise ConfigurationError(f"Failed to initialize Google Admin service: {e}")

        return self._admin_service

    def _get_reports_service(self) -> Any:
        """Get or create Admin SDK Reports service."""
        if self._reports_service is None:
            try:
                from google.oauth2 import service_account
                from googleapiclient.discovery import build

                credentials = service_account.Credentials.from_service_account_file(
                    self.config.credentials_file,
                    scopes=[
                        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                        "https://www.googleapis.com/auth/admin.reports.usage.readonly",
                    ],
                    subject=self.config.delegated_user,
                )
                self._reports_service = build("admin", "reports_v1", credentials=credentials)
            except ImportError:
                raise ConfigurationError(
                    "Google API client library not installed. "
                    "Install with: pip install google-api-python-client google-auth"
                )
            except Exception as e:
                raise ConfigurationError(f"Failed to initialize Google Reports service: {e}")

        return self._reports_service

    def _get_alerts_service(self) -> Any:
        """Get or create Alert Center service."""
        if self._alerts_service is None:
            try:
                from google.oauth2 import service_account
                from googleapiclient.discovery import build

                credentials = service_account.Credentials.from_service_account_file(
                    self.config.credentials_file,
                    scopes=[
                        "https://www.googleapis.com/auth/apps.alerts",
                    ],
                    subject=self.config.delegated_user,
                )
                self._alerts_service = build("alertcenter", "v1beta1", credentials=credentials)
            except ImportError:
                raise ConfigurationError(
                    "Google API client library not installed. "
                    "Install with: pip install google-api-python-client google-auth"
                )
            except Exception as e:
                raise ConfigurationError(f"Failed to initialize Google Alerts service: {e}")

        return self._alerts_service

    def validate_credentials(self) -> bool:
        """Validate Google Workspace credentials."""
        if not self.config.credentials_file:
            raise ConfigurationError("Google Workspace credentials_file is required")

        if not self.config.delegated_user:
            raise ConfigurationError("Google Workspace delegated_user (admin email) is required")

        try:
            # Test authentication by listing users (limit 1)
            service = self._get_admin_service()
            service.users().list(
                customer=self.config.customer_id,
                maxResults=1,
            ).execute()

            logger.info(f"Authenticated to Google Workspace for: {self.config.delegated_user}")
            return True
        except Exception as e:
            if "401" in str(e) or "Invalid" in str(e) or "unauthorized" in str(e).lower():
                raise ConfigurationError("Invalid Google Workspace credentials")
            raise ConfigurationError(f"Failed to validate Google Workspace credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Google Workspace."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Google Workspace evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "groups": self._collect_groups_evidence,
            "devices": self._collect_devices_evidence,
            "login_activity": self._collect_login_activity_evidence,
            "org_units": self._collect_org_units_evidence,
            "tokens": self._collect_tokens_evidence,
            "security_alerts": self._collect_security_alerts_evidence,
        }

        for evidence_type in evidence_types:
            try:
                method = collection_methods.get(evidence_type)
                if method:
                    evidence = method()
                    if evidence:
                        evidence_items.append(evidence)
            except Exception as e:
                error_msg = f"Error collecting {evidence_type}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        result = CollectionResult(
            platform=self.PLATFORM,
            evidence_items=evidence_items,
            errors=errors,
        )
        result.complete()
        return result

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Google Workspace users...")

        service = self._get_admin_service()
        users = []
        page_token = None

        while True:
            try:
                response = service.users().list(
                    customer=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                    projection="full",
                ).execute()

                users.extend(response.get("users", []))
                page_token = response.get("nextPageToken")

                if not page_token:
                    break
            except Exception as e:
                if not users:
                    raise
                logger.warning(f"Error during pagination: {e}")
                break

        # Analyze users
        active_count = 0
        suspended_count = 0
        admin_count = 0
        mfa_enabled_count = 0
        org_unit_counts: dict[str, int] = {}

        for user in users:
            if user.get("suspended", False):
                suspended_count += 1
            else:
                active_count += 1

            if user.get("isAdmin", False):
                admin_count += 1

            if user.get("isEnrolledIn2Sv", False):
                mfa_enabled_count += 1

            org_unit = user.get("orgUnitPath", "/")
            org_unit_counts[org_unit] = org_unit_counts.get(org_unit, 0) + 1

        mfa_rate = round(mfa_enabled_count / len(users) * 100, 1) if users else 0

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": [
                    {
                        "id": u.get("id"),
                        "email": u.get("primaryEmail"),
                        "name": u.get("name", {}).get("fullName"),
                        "suspended": u.get("suspended", False),
                        "is_admin": u.get("isAdmin", False),
                        "is_delegated_admin": u.get("isDelegatedAdmin", False),
                        "is_enforced_in_2sv": u.get("isEnforcedIn2Sv", False),
                        "is_enrolled_in_2sv": u.get("isEnrolledIn2Sv", False),
                        "creation_time": u.get("creationTime"),
                        "last_login_time": u.get("lastLoginTime"),
                        "org_unit_path": u.get("orgUnitPath"),
                        "recovery_email": u.get("recoveryEmail"),
                        "recovery_phone": u.get("recoveryPhone"),
                    }
                    for u in users
                ],
                "total_count": len(users),
                "active_count": active_count,
                "suspended_count": suspended_count,
                "admin_count": admin_count,
                "mfa_enabled_count": mfa_enabled_count,
                "mfa_rate": mfa_rate,
                "org_unit_distribution": org_unit_counts,
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_groups_evidence(self) -> Evidence:
        """Collect groups evidence."""
        logger.info("Collecting Google Workspace groups...")

        service = self._get_admin_service()
        groups = []
        page_token = None

        while True:
            try:
                response = service.groups().list(
                    customer=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                groups.extend(response.get("groups", []))
                page_token = response.get("nextPageToken")

                if not page_token:
                    break
            except Exception as e:
                if not groups:
                    raise
                logger.warning(f"Error during pagination: {e}")
                break

        # Get member counts for each group
        group_details = []
        for group in groups:
            member_count = 0
            try:
                members_response = service.members().list(
                    groupKey=group.get("id"),
                    maxResults=1,
                ).execute()
                # Use the group's directMembersCount if available
                member_count = group.get("directMembersCount", 0)
                if not member_count:
                    member_count = len(members_response.get("members", []))
            except Exception:
                pass

            group_details.append({
                "id": group.get("id"),
                "email": group.get("email"),
                "name": group.get("name"),
                "description": group.get("description"),
                "member_count": member_count,
                "admin_created": group.get("adminCreated", False),
            })

        admin_created_count = sum(1 for g in group_details if g.get("admin_created"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": group_details,
                "total_count": len(groups),
                "admin_created_count": admin_created_count,
                "user_created_count": len(groups) - admin_created_count,
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["groups"],
            },
        )

    def _collect_devices_evidence(self) -> Evidence:
        """Collect devices evidence (Chrome OS and mobile)."""
        logger.info("Collecting Google Workspace devices...")

        service = self._get_admin_service()

        # Collect Chrome OS devices
        chrome_devices = []
        page_token = None

        while True:
            try:
                response = service.chromeosdevices().list(
                    customerId=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                chrome_devices.extend(response.get("chromeosdevices", []))
                page_token = response.get("nextPageToken")

                if not page_token:
                    break
            except Exception as e:
                logger.warning(f"Error collecting Chrome devices: {e}")
                break

        # Collect mobile devices
        mobile_devices = []
        page_token = None

        while True:
            try:
                response = service.mobiledevices().list(
                    customerId=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                mobile_devices.extend(response.get("mobiledevices", []))
                page_token = response.get("nextPageToken")

                if not page_token:
                    break
            except Exception as e:
                logger.warning(f"Error collecting mobile devices: {e}")
                break

        # Analyze devices
        chrome_status_counts: dict[str, int] = {}
        for device in chrome_devices:
            status = device.get("status", "unknown")
            chrome_status_counts[status] = chrome_status_counts.get(status, 0) + 1

        mobile_type_counts: dict[str, int] = {}
        for device in mobile_devices:
            device_type = device.get("type", "unknown")
            mobile_type_counts[device_type] = mobile_type_counts.get(device_type, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="devices",
            raw_data={
                "chrome_devices": [
                    {
                        "id": d.get("deviceId"),
                        "serial_number": d.get("serialNumber"),
                        "model": d.get("model"),
                        "os_version": d.get("osVersion"),
                        "status": d.get("status"),
                        "last_sync": d.get("lastSync"),
                        "org_unit_path": d.get("orgUnitPath"),
                        "annotated_user": d.get("annotatedUser"),
                    }
                    for d in chrome_devices
                ],
                "mobile_devices": [
                    {
                        "id": d.get("deviceId"),
                        "serial_number": d.get("serialNumber"),
                        "model": d.get("model"),
                        "os": d.get("os"),
                        "type": d.get("type"),
                        "status": d.get("status"),
                        "last_sync": d.get("lastSync"),
                        "email": d.get("email", [None])[0] if d.get("email") else None,
                    }
                    for d in mobile_devices
                ],
                "chrome_device_count": len(chrome_devices),
                "mobile_device_count": len(mobile_devices),
                "total_count": len(chrome_devices) + len(mobile_devices),
                "chrome_status_counts": chrome_status_counts,
                "mobile_type_counts": mobile_type_counts,
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["devices"],
            },
        )

    def _collect_login_activity_evidence(self) -> Evidence:
        """Collect login activity evidence."""
        logger.info("Collecting Google Workspace login activity...")

        service = self._get_reports_service()

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        activities = []
        page_token = None

        while True:
            try:
                response = service.activities().list(
                    userKey="all",
                    applicationName="login",
                    startTime=since_str,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                activities.extend(response.get("items", []))
                page_token = response.get("nextPageToken")

                if not page_token:
                    break
            except Exception as e:
                if not activities:
                    raise
                logger.warning(f"Error during pagination: {e}")
                break

        # Analyze login activity
        success_count = 0
        failure_count = 0
        suspicious_count = 0
        login_types: dict[str, int] = {}

        for activity in activities:
            events = activity.get("events", [])
            for event in events:
                event_name = event.get("name", "")
                login_types[event_name] = login_types.get(event_name, 0) + 1

                if event_name == "login_success":
                    success_count += 1
                elif event_name == "login_failure":
                    failure_count += 1
                elif event_name in ("suspicious_login", "suspicious_login_less_secure_app"):
                    suspicious_count += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="login_activity",
            raw_data={
                "activities": [
                    {
                        "id": a.get("id", {}).get("uniqueQualifier"),
                        "time": a.get("id", {}).get("time"),
                        "actor_email": a.get("actor", {}).get("email"),
                        "ip_address": a.get("ipAddress"),
                        "events": [
                            {
                                "name": e.get("name"),
                                "type": e.get("type"),
                            }
                            for e in a.get("events", [])
                        ],
                    }
                    for a in activities[:1000]  # Limit to 1000 for evidence
                ],
                "total_count": len(activities),
                "success_count": success_count,
                "failure_count": failure_count,
                "suspicious_count": suspicious_count,
                "login_types": login_types,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["login_activity"],
            },
        )

    def _collect_org_units_evidence(self) -> Evidence:
        """Collect organizational units evidence."""
        logger.info("Collecting Google Workspace org units...")

        service = self._get_admin_service()

        try:
            response = service.orgunits().list(
                customerId=self.config.customer_id,
                type="all",
            ).execute()

            org_units = response.get("organizationUnits", [])
        except Exception as e:
            logger.error(f"Error collecting org units: {e}")
            org_units = []

        # Build hierarchy
        root_units = [ou for ou in org_units if ou.get("parentOrgUnitPath") == "/"]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="org_units",
            raw_data={
                "org_units": [
                    {
                        "id": ou.get("orgUnitId"),
                        "name": ou.get("name"),
                        "path": ou.get("orgUnitPath"),
                        "parent_path": ou.get("parentOrgUnitPath"),
                        "description": ou.get("description"),
                        "block_inheritance": ou.get("blockInheritance", False),
                    }
                    for ou in org_units
                ],
                "total_count": len(org_units),
                "root_unit_count": len(root_units),
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["org_units"],
            },
        )

    def _collect_tokens_evidence(self) -> Evidence:
        """Collect OAuth tokens evidence."""
        logger.info("Collecting Google Workspace tokens...")

        service = self._get_admin_service()

        # Get all users first (limited set for token collection)
        users = []
        try:
            response = service.users().list(
                customer=self.config.customer_id,
                maxResults=100,  # Limit users for token collection
            ).execute()
            users = response.get("users", [])
        except Exception as e:
            logger.warning(f"Error getting users for token collection: {e}")

        # Collect tokens for each user
        all_tokens = []
        app_counts: dict[str, int] = {}

        for user in users:
            user_email = user.get("primaryEmail")
            try:
                response = service.tokens().list(userKey=user_email).execute()
                tokens = response.get("items", [])

                for token in tokens:
                    app_name = token.get("displayText", "Unknown")
                    app_counts[app_name] = app_counts.get(app_name, 0) + 1

                    all_tokens.append({
                        "user_email": user_email,
                        "client_id": token.get("clientId"),
                        "display_text": app_name,
                        "scopes": token.get("scopes", []),
                        "native_app": token.get("nativeApp", False),
                    })
            except Exception:
                # Token access might be restricted for some users
                pass

        # Identify high-risk scopes
        high_risk_tokens = []
        high_risk_scopes = [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/admin",
        ]

        for token in all_tokens:
            scopes = token.get("scopes", [])
            if any(s in scopes for s in high_risk_scopes):
                high_risk_tokens.append(token)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="tokens",
            raw_data={
                "tokens": all_tokens,
                "total_count": len(all_tokens),
                "unique_apps": len(app_counts),
                "app_counts": app_counts,
                "high_risk_token_count": len(high_risk_tokens),
                "users_analyzed": len(users),
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["tokens"],
            },
        )

    def _collect_security_alerts_evidence(self) -> Evidence:
        """Collect security alerts evidence."""
        logger.info("Collecting Google Workspace security alerts...")

        try:
            service = self._get_alerts_service()

            alerts = []
            page_token = None

            while True:
                try:
                    response = service.alerts().list(
                        pageSize=self.config.page_size,
                        pageToken=page_token,
                    ).execute()

                    alerts.extend(response.get("alerts", []))
                    page_token = response.get("nextPageToken")

                    if not page_token:
                        break
                except Exception as e:
                    if not alerts:
                        raise
                    logger.warning(f"Error during pagination: {e}")
                    break

        except Exception as e:
            logger.warning(f"Error collecting security alerts: {e}")
            alerts = []

        # Categorize alerts
        type_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}

        for alert in alerts:
            alert_type = alert.get("type", "unknown")
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1

            status = alert.get("metadata", {}).get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_alerts",
            raw_data={
                "alerts": [
                    {
                        "id": a.get("alertId"),
                        "type": a.get("type"),
                        "source": a.get("source"),
                        "create_time": a.get("createTime"),
                        "start_time": a.get("startTime"),
                        "end_time": a.get("endTime"),
                        "status": a.get("metadata", {}).get("status"),
                        "severity": a.get("metadata", {}).get("severity"),
                    }
                    for a in alerts
                ],
                "total_count": len(alerts),
                "type_counts": type_counts,
                "status_counts": status_counts,
            },
            metadata={
                "source": "collector:google_workspace",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["security_alerts"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Google Workspace."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Google Workspace resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "gws_user": self._collect_user_resources,
            "gws_group": self._collect_group_resources,
            "gws_device": self._collect_device_resources,
            "gws_org_unit": self._collect_org_unit_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type}: {e}")

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Google Workspace user resources...")
        resources = []

        service = self._get_admin_service()
        page_token = None

        while True:
            try:
                response = service.users().list(
                    customer=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                for user in response.get("users", []):
                    resources.append(
                        Resource(
                            id=user.get("id", ""),
                            type="gws_user",
                            provider="google_workspace",
                            region="global",
                            name=user.get("primaryEmail", ""),
                            tags=[],
                            metadata={
                                "full_name": user.get("name", {}).get("fullName"),
                                "suspended": user.get("suspended", False),
                                "is_admin": user.get("isAdmin", False),
                                "is_enrolled_in_2sv": user.get("isEnrolledIn2Sv", False),
                                "org_unit_path": user.get("orgUnitPath"),
                                "last_login_time": user.get("lastLoginTime"),
                            },
                            raw_data=user,
                        )
                    )

                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            except Exception as e:
                if not resources:
                    raise
                logger.warning(f"Error during pagination: {e}")
                break

        return resources

    def _collect_group_resources(self) -> list[Resource]:
        """Collect group resources."""
        logger.info("Collecting Google Workspace group resources...")
        resources = []

        service = self._get_admin_service()
        page_token = None

        while True:
            try:
                response = service.groups().list(
                    customer=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                for group in response.get("groups", []):
                    resources.append(
                        Resource(
                            id=group.get("id", ""),
                            type="gws_group",
                            provider="google_workspace",
                            region="global",
                            name=group.get("email", ""),
                            tags=[],
                            metadata={
                                "name": group.get("name"),
                                "description": group.get("description"),
                                "member_count": group.get("directMembersCount", 0),
                                "admin_created": group.get("adminCreated", False),
                            },
                            raw_data=group,
                        )
                    )

                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            except Exception as e:
                if not resources:
                    raise
                logger.warning(f"Error during pagination: {e}")
                break

        return resources

    def _collect_device_resources(self) -> list[Resource]:
        """Collect device resources."""
        logger.info("Collecting Google Workspace device resources...")
        resources = []

        service = self._get_admin_service()

        # Chrome devices
        page_token = None
        while True:
            try:
                response = service.chromeosdevices().list(
                    customerId=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                for device in response.get("chromeosdevices", []):
                    resources.append(
                        Resource(
                            id=device.get("deviceId", ""),
                            type="gws_device",
                            provider="google_workspace",
                            region="global",
                            name=device.get("serialNumber", ""),
                            tags=["chromeos"],
                            metadata={
                                "model": device.get("model"),
                                "os_version": device.get("osVersion"),
                                "status": device.get("status"),
                                "org_unit_path": device.get("orgUnitPath"),
                            },
                            raw_data=device,
                        )
                    )

                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            except Exception as e:
                logger.warning(f"Error collecting Chrome devices: {e}")
                break

        # Mobile devices
        page_token = None
        while True:
            try:
                response = service.mobiledevices().list(
                    customerId=self.config.customer_id,
                    maxResults=self.config.page_size,
                    pageToken=page_token,
                ).execute()

                for device in response.get("mobiledevices", []):
                    resources.append(
                        Resource(
                            id=device.get("deviceId", ""),
                            type="gws_device",
                            provider="google_workspace",
                            region="global",
                            name=device.get("serialNumber", ""),
                            tags=["mobile", device.get("type", "unknown")],
                            metadata={
                                "model": device.get("model"),
                                "os": device.get("os"),
                                "type": device.get("type"),
                                "status": device.get("status"),
                            },
                            raw_data=device,
                        )
                    )

                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            except Exception as e:
                logger.warning(f"Error collecting mobile devices: {e}")
                break

        return resources

    def _collect_org_unit_resources(self) -> list[Resource]:
        """Collect org unit resources."""
        logger.info("Collecting Google Workspace org unit resources...")
        resources = []

        service = self._get_admin_service()

        try:
            response = service.orgunits().list(
                customerId=self.config.customer_id,
                type="all",
            ).execute()

            for ou in response.get("organizationUnits", []):
                resources.append(
                    Resource(
                        id=ou.get("orgUnitId", ""),
                        type="gws_org_unit",
                        provider="google_workspace",
                        region="global",
                        name=ou.get("name", ""),
                        tags=[],
                        metadata={
                            "path": ou.get("orgUnitPath"),
                            "parent_path": ou.get("parentOrgUnitPath"),
                            "description": ou.get("description"),
                            "block_inheritance": ou.get("blockInheritance", False),
                        },
                        raw_data=ou,
                    )
                )
        except Exception as e:
            logger.error(f"Error collecting org units: {e}")

        return resources
