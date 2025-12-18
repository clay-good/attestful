"""
Zoom collector for Attestful.

Collects communications, meeting security, and user management evidence
from Zoom for compliance frameworks including SOC 2, NIST 800-53,
ISO 27001, and HITRUST.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


@dataclass
class ZoomCollectorConfig:
    """Configuration for Zoom collector."""

    # OAuth credentials (Server-to-Server OAuth app)
    account_id: str = ""
    client_id: str = ""
    client_secret: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90


class ZoomCollector(BaseCollector):
    """
    Zoom collector for communications and meeting security evidence.

    Collects evidence related to:
    - Users and their roles/permissions
    - Account settings and security configurations
    - Meeting settings and defaults
    - Recording settings
    - SSO and authentication settings
    - Groups and roles
    - Webinar settings (if enabled)

    Evidence Types:
    - users: User accounts with roles and settings
    - account_settings: Account-wide security settings
    - meeting_settings: Meeting security configurations
    - recording_settings: Recording and storage settings
    - security_settings: Authentication and SSO settings
    - groups: User groups
    - roles: Role definitions and permissions
    - signin_signout_activities: Sign-in/sign-out audit events

    Resource Types:
    - zoom_user: User resources
    - zoom_group: Group resources
    - zoom_role: Role resources
    - zoom_room: Zoom Room resources

    Example:
        collector = ZoomCollector(
            config=ZoomCollectorConfig(
                account_id="your_account_id",
                client_id="your_client_id",
                client_secret="your_client_secret",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "account_settings", "security_settings"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["zoom_user", "zoom_group"]
        )
    """

    PLATFORM = "zoom"

    metadata = CollectorMetadata(
        name="ZoomCollector",
        platform="zoom",
        description="Collects communications and meeting security evidence from Zoom",
        mode=CollectorMode.BOTH,
        resource_types=[
            "zoom_user",
            "zoom_group",
            "zoom_role",
            "zoom_room",
        ],
        evidence_types=[
            "users",
            "account_settings",
            "meeting_settings",
            "recording_settings",
            "security_settings",
            "groups",
            "roles",
            "signin_signout_activities",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "zoom_user",
        "zoom_group",
        "zoom_role",
        "zoom_room",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "account_settings",
        "meeting_settings",
        "recording_settings",
        "security_settings",
        "groups",
        "roles",
        "signin_signout_activities",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.d"],
        },
        "account_settings": {
            "soc2": ["CC5.2", "CC6.1", "CC6.6"],
            "nist_800_53": ["AC-3", "AC-17", "CM-6"],
            "iso_27001": ["A.9.1.2", "A.13.1.1", "A.14.1.2"],
            "hitrust": ["01.c", "09.m"],
        },
        "meeting_settings": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["AC-3", "AC-17", "SC-8"],
            "iso_27001": ["A.13.1.1", "A.13.2.1", "A.14.1.2"],
            "hitrust": ["09.m", "09.s"],
        },
        "recording_settings": {
            "soc2": ["CC6.1", "CC6.7", "CC7.2"],
            "nist_800_53": ["AU-4", "AU-9", "SC-28"],
            "iso_27001": ["A.12.4.1", "A.18.1.3"],
            "hitrust": ["09.aa", "06.c"],
        },
        "security_settings": {
            "soc2": ["CC6.1", "CC6.2", "CC6.6"],
            "nist_800_53": ["AC-2", "AC-7", "IA-2", "IA-5"],
            "iso_27001": ["A.9.2.1", "A.9.4.2", "A.9.4.3"],
            "hitrust": ["01.b", "01.d", "01.q"],
        },
        "groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1"],
            "hitrust": ["01.c"],
        },
        "roles": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.3"],
            "hitrust": ["01.c", "01.e"],
        },
        "signin_signout_activities": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    def __init__(self, config: ZoomCollectorConfig | None = None):
        """Initialize the Zoom collector."""
        self.config = config or ZoomCollectorConfig()
        self._session: requests.Session | None = None
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    @property
    def api_url(self) -> str:
        """Get the Zoom API base URL."""
        return "https://api.zoom.us/v2"

    def _create_session(self) -> requests.Session:
        """Create an authenticated session with retry logic."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"

        return session

    def _get_access_token(self) -> str:
        """Get OAuth access token using Server-to-Server OAuth."""
        # Check if we have a valid cached token
        if self._access_token and self._token_expires_at:
            if datetime.now(timezone.utc) < self._token_expires_at:
                return self._access_token

        # Get new token
        token_url = f"https://zoom.us/oauth/token?grant_type=account_credentials&account_id={self.config.account_id}"

        try:
            response = requests.post(
                token_url,
                auth=(self.config.client_id, self.config.client_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()

            self._access_token = data["access_token"]
            # Token typically expires in 1 hour, refresh 5 minutes early
            expires_in = data.get("expires_in", 3600)
            self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 300)

            return self._access_token

        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ConfigurationError("Invalid Zoom OAuth credentials")
            raise ConfigurationError(f"Zoom OAuth error: {e}")
        except requests.RequestException as e:
            raise ConfigurationError(f"Failed to obtain Zoom access token: {e}")

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated API request."""
        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        url = f"{self.api_url}/{endpoint}"

        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=data,
                headers=headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.RequestException as e:
            logger.warning(f"API request failed: {endpoint} - {e}")
            raise

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through Zoom API results."""
        params = params or {}
        params["page_size"] = self.config.page_size
        next_page_token = None

        while True:
            if next_page_token:
                params["next_page_token"] = next_page_token

            try:
                data = self._make_request("GET", endpoint, params=params)

                # Get items from response
                if results_key:
                    items = data.get(results_key, [])
                else:
                    # Try common keys
                    for key in ["users", "groups", "roles", "rooms", "activity_logs"]:
                        if key in data:
                            items = data[key]
                            break
                    else:
                        items = []

                for item in items:
                    yield item

                # Check for next page
                next_page_token = data.get("next_page_token", "")
                if not next_page_token:
                    break

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate Zoom credentials."""
        if not self.config.account_id:
            raise ConfigurationError("Zoom account_id is required")
        if not self.config.client_id:
            raise ConfigurationError("Zoom client_id is required")
        if not self.config.client_secret:
            raise ConfigurationError("Zoom client_secret is required")

        try:
            # Try to get an access token and make a simple API call
            self._get_access_token()
            # Verify by calling users endpoint
            self._make_request("GET", "users", params={"page_size": 1})
            logger.info("Zoom credentials validated successfully")
            return True
        except ConfigurationError:
            raise
        except Exception as e:
            raise ConfigurationError(f"Failed to validate Zoom credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Zoom."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Zoom evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "account_settings": self._collect_account_settings_evidence,
            "meeting_settings": self._collect_meeting_settings_evidence,
            "recording_settings": self._collect_recording_settings_evidence,
            "security_settings": self._collect_security_settings_evidence,
            "groups": self._collect_groups_evidence,
            "roles": self._collect_roles_evidence,
            "signin_signout_activities": self._collect_signin_activities_evidence,
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
        logger.info("Collecting Zoom users...")
        users = []

        for user in self._paginate("users", results_key="users"):
            users.append({
                "id": user.get("id"),
                "email": user.get("email"),
                "first_name": user.get("first_name"),
                "last_name": user.get("last_name"),
                "display_name": user.get("display_name"),
                "type": user.get("type"),  # 1=Basic, 2=Licensed, 3=On-prem
                "role_name": user.get("role_name"),
                "role_id": user.get("role_id"),
                "pmi": user.get("pmi"),
                "timezone": user.get("timezone"),
                "verified": user.get("verified"),
                "created_at": user.get("created_at"),
                "last_login_time": user.get("last_login_time"),
                "status": user.get("status"),  # active, inactive, pending
                "dept": user.get("dept"),
                "group_ids": user.get("group_ids", []),
            })

        # Categorize by type
        by_type = {}
        type_names = {1: "basic", 2: "licensed", 3: "on_prem", 99: "none"}
        for u in users:
            user_type = type_names.get(u.get("type"), "unknown")
            by_type[user_type] = by_type.get(user_type, 0) + 1

        # Categorize by status
        by_status = {}
        for u in users:
            status = u.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "by_type": by_type,
                "by_status": by_status,
                "licensed_count": by_type.get("licensed", 0),
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_account_settings_evidence(self) -> Evidence:
        """Collect account settings evidence."""
        logger.info("Collecting Zoom account settings...")
        settings = {}

        try:
            data = self._make_request("GET", "accounts/me/settings")
            settings = {
                "schedule_meeting": data.get("schedule_meeting", {}),
                "in_meeting": data.get("in_meeting", {}),
                "email_notification": data.get("email_notification", {}),
                "zoom_rooms": data.get("zoom_rooms", {}),
                "recording": data.get("recording", {}),
                "telephony": data.get("telephony", {}),
                "integration": data.get("integration", {}),
                "feature": data.get("feature", {}),
            }
        except requests.RequestException as e:
            logger.warning(f"Error collecting account settings: {e}")

        # Extract key security settings
        schedule = settings.get("schedule_meeting", {})
        in_meeting = settings.get("in_meeting", {})

        security_summary = {
            "password_required": schedule.get("require_password_for_scheduling_new_meetings", False),
            "waiting_room_enabled": schedule.get("waiting_room", False),
            "pmi_password_required": schedule.get("require_password_for_pmi_meetings") != "none",
            "encryption_type": in_meeting.get("encryption_type", "unknown"),
            "e2ee_enabled": in_meeting.get("e2e_encryption", False),
            "screen_sharing_who_can_share": in_meeting.get("who_can_share_screen", "unknown"),
            "allow_removed_participants_rejoin": in_meeting.get("allow_participants_to_rename", False),
        }

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="account_settings",
            raw_data={
                "settings": settings,
                "security_summary": security_summary,
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["account_settings"],
            },
        )

    def _collect_meeting_settings_evidence(self) -> Evidence:
        """Collect meeting settings evidence."""
        logger.info("Collecting Zoom meeting settings...")
        meeting_settings = {}

        try:
            data = self._make_request("GET", "accounts/me/settings")
            meeting_settings = {
                "schedule_meeting": data.get("schedule_meeting", {}),
                "in_meeting": data.get("in_meeting", {}),
            }
        except requests.RequestException as e:
            logger.warning(f"Error collecting meeting settings: {e}")

        schedule = meeting_settings.get("schedule_meeting", {})
        in_meeting = meeting_settings.get("in_meeting", {})

        # Key meeting security configurations
        security_config = {
            # Password settings
            "require_password_instant_meetings": schedule.get("require_password_for_instant_meetings", False),
            "require_password_scheduled_meetings": schedule.get("require_password_for_scheduling_new_meetings", False),
            "require_password_pmi": schedule.get("require_password_for_pmi_meetings", "none"),
            "password_requirements_enforced": schedule.get("meeting_password_requirement", {}).get("consecutive_characters_length", 0) > 0,

            # Waiting room
            "waiting_room_enabled": schedule.get("waiting_room", False),
            "waiting_room_options": schedule.get("waiting_room_options", {}),

            # Host/Participant controls
            "host_video_on_join": schedule.get("host_video", False),
            "participant_video_on_join": schedule.get("participant_video", False),
            "join_before_host": schedule.get("join_before_host", False),
            "mute_upon_entry": schedule.get("mute_upon_entry", False),

            # Security features
            "screen_sharing": in_meeting.get("screen_sharing", False),
            "who_can_share_screen": in_meeting.get("who_can_share_screen", "all"),
            "annotation_disabled": in_meeting.get("annotation", False),
            "whiteboard_disabled": in_meeting.get("whiteboard", False),
            "allow_unmute_self": in_meeting.get("allow_participants_to_unmute", False),
            "chat_enabled": in_meeting.get("chat", False),
            "private_chat_disabled": not in_meeting.get("private_chat", True),
            "file_transfer_disabled": not in_meeting.get("file_transfer", True),

            # Recording consent
            "recording_consent_required": in_meeting.get("recording_consent", False),
        }

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="meeting_settings",
            raw_data={
                "meeting_settings": meeting_settings,
                "security_configuration": security_config,
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["meeting_settings"],
            },
        )

    def _collect_recording_settings_evidence(self) -> Evidence:
        """Collect recording settings evidence."""
        logger.info("Collecting Zoom recording settings...")
        recording_settings = {}

        try:
            data = self._make_request("GET", "accounts/me/settings")
            recording_settings = data.get("recording", {})
        except requests.RequestException as e:
            logger.warning(f"Error collecting recording settings: {e}")

        # Key recording configurations
        recording_config = {
            # Cloud recording
            "cloud_recording": recording_settings.get("cloud_recording", False),
            "cloud_recording_available_for_users": recording_settings.get("cloud_recording_available_for_users", False),
            "auto_recording": recording_settings.get("auto_recording", "none"),

            # Local recording
            "local_recording": recording_settings.get("local_recording", False),
            "host_delete_cloud_recording": recording_settings.get("host_delete_cloud_recording", False),

            # Access controls
            "recording_password_requirement": recording_settings.get("recording_password_requirement", {}),
            "required_password_for_shared_cloud_recordings": recording_settings.get("required_password_for_shared_cloud_recordings", False),

            # Storage and retention
            "auto_delete_cmr": recording_settings.get("auto_delete_cmr", False),
            "auto_delete_cmr_days": recording_settings.get("auto_delete_cmr_days", 0),

            # Transcript
            "cloud_recording_transcript": recording_settings.get("cloud_recording_transcript", False),
            "save_chat_text": recording_settings.get("save_chat_text", False),
        }

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="recording_settings",
            raw_data={
                "recording_settings": recording_settings,
                "recording_configuration": recording_config,
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["recording_settings"],
            },
        )

    def _collect_security_settings_evidence(self) -> Evidence:
        """Collect security settings evidence."""
        logger.info("Collecting Zoom security settings...")
        security_settings = {}

        try:
            data = self._make_request("GET", "accounts/me/settings")
            security_settings = {
                "security": data.get("security", {}),
                "feature": data.get("feature", {}),
            }
        except requests.RequestException as e:
            logger.warning(f"Error collecting security settings: {e}")

        security = security_settings.get("security", {})
        feature = security_settings.get("feature", {})

        # Key security configurations
        security_config = {
            # Authentication
            "admin_change_name_pic": security.get("admin_change_name_pic", False),
            "admin_change_user_info": security.get("admin_change_user_info", False),
            "hide_billing_info": security.get("hide_billing_info", False),

            # Sign-in options
            "sign_in_with_work_email": security.get("sign_in_with_work_email", False),
            "sign_in_with_google": security.get("sign_in_with_google", False),
            "sign_in_with_facebook": security.get("sign_in_with_facebook", False),
            "sign_in_with_apple": security.get("sign_in_with_apple", False),
            "sign_in_with_sso": security.get("sign_in_with_sso", False),

            # Password requirements
            "password_minimum_length": security.get("password_minimum_length", 0),
            "password_have_special_char": security.get("password_have_special_char", False),
            "password_have_number": security.get("password_have_number", False),
            "password_have_upper_and_lower": security.get("password_have_upper_and_lower", False),

            # Other security
            "embed_password_in_join_link": security.get("embed_password_in_join_link", False),
            "waiting_room": security.get("waiting_room", False),

            # Features
            "zoom_phone": feature.get("zoom_phone", False),
            "concurrent_meeting": feature.get("concurrent_meeting", False),
            "webinar": feature.get("webinar", False),
            "zoom_events": feature.get("zoom_events", False),
            "large_meeting": feature.get("large_meeting", False),
        }

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_settings",
            raw_data={
                "security_settings": security_settings,
                "security_configuration": security_config,
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["security_settings"],
            },
        )

    def _collect_groups_evidence(self) -> Evidence:
        """Collect groups evidence."""
        logger.info("Collecting Zoom groups...")
        groups = []

        for group in self._paginate("groups", results_key="groups"):
            group_detail = {
                "id": group.get("id"),
                "name": group.get("name"),
                "total_members": group.get("total_members", 0),
            }

            # Try to get group members count
            try:
                members_data = self._make_request(
                    "GET",
                    f"groups/{group['id']}/members",
                    params={"page_size": 1},
                )
                group_detail["members_count"] = members_data.get("total_records", 0)
            except requests.RequestException:
                group_detail["members_count"] = group.get("total_members", 0)

            groups.append(group_detail)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": groups,
                "total_count": len(groups),
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["groups"],
            },
        )

    def _collect_roles_evidence(self) -> Evidence:
        """Collect roles evidence."""
        logger.info("Collecting Zoom roles...")
        roles = []

        for role in self._paginate("roles", results_key="roles"):
            role_detail = {
                "id": role.get("id"),
                "name": role.get("name"),
                "description": role.get("description"),
                "total_members": role.get("total_members", 0),
            }

            # Try to get role privileges
            try:
                priv_data = self._make_request("GET", f"roles/{role['id']}")
                role_detail["privileges"] = priv_data.get("privileges", [])
                role_detail["sub_account_privileges"] = priv_data.get("sub_account_privileges", {})
            except requests.RequestException:
                role_detail["privileges"] = []

            roles.append(role_detail)

        # Categorize by type
        admin_roles = [r for r in roles if "admin" in r.get("name", "").lower()]
        member_roles = [r for r in roles if r not in admin_roles]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="roles",
            raw_data={
                "roles": roles,
                "total_count": len(roles),
                "admin_roles_count": len(admin_roles),
                "member_roles_count": len(member_roles),
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["roles"],
            },
        )

    def _collect_signin_activities_evidence(self) -> Evidence:
        """Collect sign-in/sign-out activity evidence."""
        logger.info("Collecting Zoom sign-in activities...")
        activities = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        try:
            # Sign-in/sign-out activities
            params = {
                "from": cutoff_date.strftime("%Y-%m-%d"),
                "to": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            }

            for activity in self._paginate("report/activities", params=params, results_key="activity_logs"):
                activities.append({
                    "email": activity.get("email"),
                    "time": activity.get("time"),
                    "type": activity.get("type"),  # Sign-in, Sign-out
                    "ip_address": activity.get("ip_address"),
                    "client_type": activity.get("client_type"),
                    "version": activity.get("version"),
                })

        except requests.RequestException as e:
            logger.warning(f"Error collecting sign-in activities: {e}")

        # Categorize by type
        by_type = {}
        for a in activities:
            activity_type = a.get("type", "unknown")
            by_type[activity_type] = by_type.get(activity_type, 0) + 1

        # Categorize by client type
        by_client = {}
        for a in activities:
            client = a.get("client_type", "unknown")
            by_client[client] = by_client.get(client, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="signin_signout_activities",
            raw_data={
                "activities": activities,
                "total_count": len(activities),
                "by_type": by_type,
                "by_client_type": by_client,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:zoom",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["signin_signout_activities"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Zoom for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Zoom resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "zoom_user": self._collect_user_resources,
            "zoom_group": self._collect_group_resources,
            "zoom_role": self._collect_role_resources,
            "zoom_room": self._collect_room_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Zoom user resources...")
        resources = []
        type_names = {1: "basic", 2: "licensed", 3: "on_prem", 99: "none"}

        for user in self._paginate("users", results_key="users"):
            user_type = type_names.get(user.get("type"), "unknown")
            resources.append(
                Resource(
                    id=str(user.get("id", "")),
                    type="zoom_user",
                    provider="zoom",
                    region="global",
                    name=user.get("email", "Unknown"),
                    tags={
                        "type": user_type,
                        "status": user.get("status", "unknown"),
                        "verified": str(user.get("verified", False)).lower(),
                    },
                    metadata={
                        "email": user.get("email"),
                        "first_name": user.get("first_name"),
                        "last_name": user.get("last_name"),
                        "display_name": user.get("display_name"),
                        "type": user.get("type"),
                        "type_name": user_type,
                        "role_name": user.get("role_name"),
                        "role_id": user.get("role_id"),
                        "status": user.get("status"),
                        "verified": user.get("verified"),
                        "created_at": user.get("created_at"),
                        "last_login_time": user.get("last_login_time"),
                        "dept": user.get("dept"),
                        "group_ids": user.get("group_ids", []),
                    },
                    raw_data=user,
                )
            )

        return resources

    def _collect_group_resources(self) -> list[Resource]:
        """Collect group resources."""
        logger.info("Collecting Zoom group resources...")
        resources = []

        for group in self._paginate("groups", results_key="groups"):
            resources.append(
                Resource(
                    id=str(group.get("id", "")),
                    type="zoom_group",
                    provider="zoom",
                    region="global",
                    name=group.get("name", "Unknown"),
                    tags={
                        "total_members": str(group.get("total_members", 0)),
                    },
                    metadata={
                        "name": group.get("name"),
                        "total_members": group.get("total_members", 0),
                    },
                    raw_data=group,
                )
            )

        return resources

    def _collect_role_resources(self) -> list[Resource]:
        """Collect role resources."""
        logger.info("Collecting Zoom role resources...")
        resources = []

        for role in self._paginate("roles", results_key="roles"):
            is_admin = "admin" in role.get("name", "").lower()
            resources.append(
                Resource(
                    id=str(role.get("id", "")),
                    type="zoom_role",
                    provider="zoom",
                    region="global",
                    name=role.get("name", "Unknown"),
                    tags={
                        "is_admin": str(is_admin).lower(),
                        "total_members": str(role.get("total_members", 0)),
                    },
                    metadata={
                        "name": role.get("name"),
                        "description": role.get("description"),
                        "total_members": role.get("total_members", 0),
                        "is_admin_role": is_admin,
                    },
                    raw_data=role,
                )
            )

        return resources

    def _collect_room_resources(self) -> list[Resource]:
        """Collect Zoom Room resources."""
        logger.info("Collecting Zoom room resources...")
        resources = []

        try:
            for room in self._paginate("rooms", results_key="rooms"):
                resources.append(
                    Resource(
                        id=str(room.get("id", "")),
                        type="zoom_room",
                        provider="zoom",
                        region="global",
                        name=room.get("name", "Unknown"),
                        tags={
                            "status": room.get("status", "unknown"),
                            "room_type": room.get("type", "unknown"),
                        },
                        metadata={
                            "name": room.get("name"),
                            "room_type": room.get("type"),
                            "status": room.get("status"),
                            "location_id": room.get("location_id"),
                            "device_ip": room.get("device_ip"),
                            "camera": room.get("camera"),
                            "microphone": room.get("microphone"),
                            "speaker": room.get("speaker"),
                        },
                        raw_data=room,
                    )
                )
        except requests.RequestException as e:
            logger.warning(f"Error collecting Zoom Rooms (may require additional license): {e}")

        return resources
