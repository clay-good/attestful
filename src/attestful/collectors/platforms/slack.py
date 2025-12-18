"""
Slack collector for Attestful.

Collects communications, workspace security, and user management evidence
from Slack for compliance frameworks including SOC 2, NIST 800-53,
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
class SlackCollectorConfig:
    """Configuration for Slack collector."""

    # Bot OAuth Token (xoxb-...)
    bot_token: str = ""

    # User OAuth Token for admin APIs (xoxp-...) - optional, enables more features
    user_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 200

    # Collection options
    days_of_history: int = 90


class SlackCollector(BaseCollector):
    """
    Slack collector for communications and workspace security evidence.

    Collects evidence related to:
    - Users and their profiles
    - Channels and their configurations
    - User groups (teams)
    - Workspace settings and policies
    - Apps and integrations
    - Access logs (Enterprise Grid only)

    Evidence Types:
    - users: Workspace users with profiles
    - channels: Public and private channels
    - user_groups: User groups/teams
    - team_info: Workspace/team information
    - apps: Installed apps and integrations
    - access_logs: Access and authentication logs (Enterprise)

    Resource Types:
    - slack_user: User resources
    - slack_channel: Channel resources
    - slack_user_group: User group resources
    - slack_app: App resources

    Example:
        collector = SlackCollector(
            config=SlackCollectorConfig(
                bot_token="xoxb-xxx",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "channels", "team_info"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["slack_user", "slack_channel"]
        )
    """

    PLATFORM = "slack"

    metadata = CollectorMetadata(
        name="SlackCollector",
        platform="slack",
        description="Collects communications and workspace security evidence from Slack",
        mode=CollectorMode.BOTH,
        resource_types=[
            "slack_user",
            "slack_channel",
            "slack_user_group",
            "slack_app",
        ],
        evidence_types=[
            "users",
            "channels",
            "user_groups",
            "team_info",
            "apps",
            "access_logs",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "slack_user",
        "slack_channel",
        "slack_user_group",
        "slack_app",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "channels",
        "user_groups",
        "team_info",
        "apps",
        "access_logs",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.d"],
        },
        "channels": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["AC-3", "AC-4", "SC-7"],
            "iso_27001": ["A.13.1.1", "A.13.2.1"],
            "hitrust": ["09.m", "09.s"],
        },
        "user_groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1"],
            "hitrust": ["01.c"],
        },
        "team_info": {
            "soc2": ["CC5.2", "CC6.1", "CC6.6"],
            "nist_800_53": ["AC-3", "CM-6", "CM-7"],
            "iso_27001": ["A.9.1.2", "A.14.1.2"],
            "hitrust": ["01.c", "09.b"],
        },
        "apps": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["CM-7", "CM-11", "SA-22"],
            "iso_27001": ["A.12.5.1", "A.12.6.2"],
            "hitrust": ["09.j", "10.h"],
        },
        "access_logs": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    def __init__(self, config: SlackCollectorConfig | None = None):
        """Initialize the Slack collector."""
        self.config = config or SlackCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    @property
    def api_url(self) -> str:
        """Get the Slack API base URL."""
        return "https://slack.com/api"

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

        # Set default headers
        session.headers["Content-Type"] = "application/json; charset=utf-8"

        return session

    def _make_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        use_user_token: bool = False,
    ) -> dict[str, Any]:
        """Make an authenticated API request."""
        token = self.config.user_token if use_user_token and self.config.user_token else self.config.bot_token
        headers = {"Authorization": f"Bearer {token}"}

        url = f"{self.api_url}/{method}"
        params = params or {}

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("ok"):
                error = data.get("error", "Unknown error")
                logger.warning(f"Slack API error for {method}: {error}")
                raise requests.RequestException(f"Slack API error: {error}")

            return data
        except requests.RequestException as e:
            logger.warning(f"API request failed: {method} - {e}")
            raise

    def _paginate(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        results_key: str = "members",
        use_user_token: bool = False,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through Slack API results using cursor-based pagination."""
        params = params or {}
        params["limit"] = self.config.page_size
        cursor = None

        while True:
            if cursor:
                params["cursor"] = cursor

            try:
                data = self._make_request(method, params=params, use_user_token=use_user_token)

                items = data.get(results_key, [])
                for item in items:
                    yield item

                # Check for next page
                response_metadata = data.get("response_metadata", {})
                cursor = response_metadata.get("next_cursor", "")
                if not cursor:
                    break

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate Slack credentials."""
        if not self.config.bot_token:
            raise ConfigurationError("Slack bot_token is required")

        try:
            # Test authentication
            data = self._make_request("auth.test")
            team_name = data.get("team", "Unknown")
            user_name = data.get("user", "Unknown")
            logger.info(f"Authenticated as {user_name} in workspace {team_name}")
            return True
        except requests.RequestException as e:
            if "invalid_auth" in str(e):
                raise ConfigurationError("Invalid Slack token")
            raise ConfigurationError(f"Failed to validate Slack credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Slack."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Slack evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "channels": self._collect_channels_evidence,
            "user_groups": self._collect_user_groups_evidence,
            "team_info": self._collect_team_info_evidence,
            "apps": self._collect_apps_evidence,
            "access_logs": self._collect_access_logs_evidence,
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
        logger.info("Collecting Slack users...")
        users = []

        for user in self._paginate("users.list", results_key="members"):
            if user.get("deleted"):
                continue  # Skip deactivated users

            profile = user.get("profile", {})
            users.append({
                "id": user.get("id"),
                "name": user.get("name"),
                "real_name": user.get("real_name") or profile.get("real_name"),
                "email": profile.get("email"),
                "is_admin": user.get("is_admin", False),
                "is_owner": user.get("is_owner", False),
                "is_primary_owner": user.get("is_primary_owner", False),
                "is_restricted": user.get("is_restricted", False),
                "is_ultra_restricted": user.get("is_ultra_restricted", False),
                "is_bot": user.get("is_bot", False),
                "is_app_user": user.get("is_app_user", False),
                "has_2fa": user.get("has_2fa", False),
                "tz": user.get("tz"),
                "updated": user.get("updated"),
            })

        # Categorize users
        admin_count = sum(1 for u in users if u.get("is_admin"))
        owner_count = sum(1 for u in users if u.get("is_owner"))
        bot_count = sum(1 for u in users if u.get("is_bot") or u.get("is_app_user"))
        guest_count = sum(1 for u in users if u.get("is_restricted") or u.get("is_ultra_restricted"))
        mfa_count = sum(1 for u in users if u.get("has_2fa"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "admin_count": admin_count,
                "owner_count": owner_count,
                "bot_count": bot_count,
                "guest_count": guest_count,
                "mfa_enabled_count": mfa_count,
            },
            metadata={
                "source": "collector:slack",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_channels_evidence(self) -> Evidence:
        """Collect channels evidence."""
        logger.info("Collecting Slack channels...")
        channels = []

        # Get public channels
        for channel in self._paginate("conversations.list", params={"types": "public_channel"}, results_key="channels"):
            channels.append(self._normalize_channel(channel, "public"))

        # Get private channels (requires appropriate permissions)
        try:
            for channel in self._paginate("conversations.list", params={"types": "private_channel"}, results_key="channels"):
                channels.append(self._normalize_channel(channel, "private"))
        except requests.RequestException:
            logger.warning("Could not fetch private channels (may need additional permissions)")

        # Categorize channels
        public_count = sum(1 for c in channels if c.get("is_private") is False)
        private_count = sum(1 for c in channels if c.get("is_private") is True)
        archived_count = sum(1 for c in channels if c.get("is_archived"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="channels",
            raw_data={
                "channels": channels,
                "total_count": len(channels),
                "public_count": public_count,
                "private_count": private_count,
                "archived_count": archived_count,
            },
            metadata={
                "source": "collector:slack",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["channels"],
            },
        )

    def _normalize_channel(self, channel: dict[str, Any], channel_type: str) -> dict[str, Any]:
        """Normalize channel data."""
        return {
            "id": channel.get("id"),
            "name": channel.get("name"),
            "is_private": channel.get("is_private", channel_type == "private"),
            "is_archived": channel.get("is_archived", False),
            "is_general": channel.get("is_general", False),
            "is_shared": channel.get("is_shared", False),
            "is_ext_shared": channel.get("is_ext_shared", False),
            "is_org_shared": channel.get("is_org_shared", False),
            "creator": channel.get("creator"),
            "created": channel.get("created"),
            "num_members": channel.get("num_members", 0),
            "topic": channel.get("topic", {}).get("value", ""),
            "purpose": channel.get("purpose", {}).get("value", ""),
        }

    def _collect_user_groups_evidence(self) -> Evidence:
        """Collect user groups evidence."""
        logger.info("Collecting Slack user groups...")
        user_groups = []

        try:
            data = self._make_request("usergroups.list", params={"include_users": "true", "include_count": "true"})
            for group in data.get("usergroups", []):
                user_groups.append({
                    "id": group.get("id"),
                    "name": group.get("name"),
                    "handle": group.get("handle"),
                    "description": group.get("description"),
                    "is_external": group.get("is_external", False),
                    "user_count": group.get("user_count", len(group.get("users", []))),
                    "users": group.get("users", []),
                    "created_by": group.get("created_by"),
                    "date_create": group.get("date_create"),
                    "date_update": group.get("date_update"),
                })
        except requests.RequestException as e:
            logger.warning(f"Error collecting user groups: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="user_groups",
            raw_data={
                "user_groups": user_groups,
                "total_count": len(user_groups),
            },
            metadata={
                "source": "collector:slack",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["user_groups"],
            },
        )

    def _collect_team_info_evidence(self) -> Evidence:
        """Collect team/workspace info evidence."""
        logger.info("Collecting Slack team info...")
        team_info = {}

        try:
            data = self._make_request("team.info")
            team = data.get("team", {})
            team_info = {
                "id": team.get("id"),
                "name": team.get("name"),
                "domain": team.get("domain"),
                "email_domain": team.get("email_domain"),
                "enterprise_id": team.get("enterprise_id"),
                "enterprise_name": team.get("enterprise_name"),
                "is_verified": team.get("is_verified", False),
                "icon": team.get("icon", {}).get("image_original"),
            }
        except requests.RequestException as e:
            logger.warning(f"Error collecting team info: {e}")

        # Try to get team preferences/settings if we have admin access
        team_settings = {}
        try:
            # This requires admin.teams:read scope
            prefs_data = self._make_request("team.preferences.list", use_user_token=True)
            team_settings = prefs_data.get("preferences", {})
        except requests.RequestException:
            logger.debug("Could not fetch team preferences (may need admin scope)")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="team_info",
            raw_data={
                "team_info": team_info,
                "team_settings": team_settings,
            },
            metadata={
                "source": "collector:slack",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["team_info"],
            },
        )

    def _collect_apps_evidence(self) -> Evidence:
        """Collect installed apps evidence."""
        logger.info("Collecting Slack apps...")
        apps = []

        try:
            # This requires admin.apps:read scope
            data = self._make_request("apps.list", use_user_token=True)
            for app in data.get("apps", []):
                apps.append({
                    "id": app.get("id"),
                    "name": app.get("name"),
                    "description": app.get("description"),
                    "is_internal": app.get("is_internal", False),
                    "is_active": app.get("is_active", True),
                    "scopes": app.get("scopes", []),
                    "date_created": app.get("date_created"),
                    "date_updated": app.get("date_updated"),
                })
        except requests.RequestException as e:
            logger.warning(f"Error collecting apps (may need admin scope): {e}")

        # If admin API not available, try to get bot/app users as proxy
        if not apps:
            try:
                for user in self._paginate("users.list", results_key="members"):
                    if user.get("is_bot") or user.get("is_app_user"):
                        apps.append({
                            "id": user.get("id"),
                            "name": user.get("real_name") or user.get("name"),
                            "is_bot": True,
                            "is_app_user": user.get("is_app_user", False),
                        })
            except requests.RequestException:
                pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="apps",
            raw_data={
                "apps": apps,
                "total_count": len(apps),
                "note": "Full app details require admin.apps:read scope" if not apps else None,
            },
            metadata={
                "source": "collector:slack",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["apps"],
            },
        )

    def _collect_access_logs_evidence(self) -> Evidence:
        """Collect access logs evidence (Enterprise Grid only)."""
        logger.info("Collecting Slack access logs...")
        access_logs = []

        try:
            # This requires admin.logs:read scope and Enterprise Grid
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

            params = {
                "count": self.config.page_size,
            }

            data = self._make_request("team.accessLogs", params=params, use_user_token=True)
            for log in data.get("logins", []):
                log_time = log.get("date_first", 0)
                if log_time and log_time < int(cutoff_date.timestamp()):
                    continue

                access_logs.append({
                    "user_id": log.get("user_id"),
                    "username": log.get("username"),
                    "date_first": log.get("date_first"),
                    "date_last": log.get("date_last"),
                    "count": log.get("count"),
                    "ip": log.get("ip"),
                    "user_agent": log.get("user_agent"),
                    "isp": log.get("isp"),
                    "country": log.get("country"),
                    "region": log.get("region"),
                })

        except requests.RequestException as e:
            logger.warning(f"Error collecting access logs (Enterprise Grid only): {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="access_logs",
            raw_data={
                "access_logs": access_logs,
                "total_count": len(access_logs),
                "days_of_history": self.config.days_of_history,
                "note": "Access logs require Enterprise Grid and admin.logs:read scope" if not access_logs else None,
            },
            metadata={
                "source": "collector:slack",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["access_logs"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Slack for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Slack resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "slack_user": self._collect_user_resources,
            "slack_channel": self._collect_channel_resources,
            "slack_user_group": self._collect_user_group_resources,
            "slack_app": self._collect_app_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Slack user resources...")
        resources = []

        for user in self._paginate("users.list", results_key="members"):
            if user.get("deleted"):
                continue

            profile = user.get("profile", {})
            is_admin = user.get("is_admin", False)
            is_owner = user.get("is_owner", False)

            # Determine user role
            if user.get("is_primary_owner"):
                role = "primary_owner"
            elif is_owner:
                role = "owner"
            elif is_admin:
                role = "admin"
            elif user.get("is_ultra_restricted"):
                role = "single_channel_guest"
            elif user.get("is_restricted"):
                role = "multi_channel_guest"
            elif user.get("is_bot"):
                role = "bot"
            else:
                role = "member"

            resources.append(
                Resource(
                    id=str(user.get("id", "")),
                    type="slack_user",
                    provider="slack",
                    region="global",
                    name=user.get("real_name") or user.get("name", "Unknown"),
                    tags={
                        "role": role,
                        "is_admin": str(is_admin).lower(),
                        "has_2fa": str(user.get("has_2fa", False)).lower(),
                        "is_bot": str(user.get("is_bot", False)).lower(),
                    },
                    metadata={
                        "id": user.get("id"),
                        "name": user.get("name"),
                        "real_name": user.get("real_name"),
                        "email": profile.get("email"),
                        "is_admin": is_admin,
                        "is_owner": is_owner,
                        "is_primary_owner": user.get("is_primary_owner", False),
                        "is_restricted": user.get("is_restricted", False),
                        "is_ultra_restricted": user.get("is_ultra_restricted", False),
                        "is_bot": user.get("is_bot", False),
                        "has_2fa": user.get("has_2fa", False),
                        "tz": user.get("tz"),
                    },
                    raw_data=user,
                )
            )

        return resources

    def _collect_channel_resources(self) -> list[Resource]:
        """Collect channel resources."""
        logger.info("Collecting Slack channel resources...")
        resources = []

        # Get public channels
        for channel in self._paginate("conversations.list", params={"types": "public_channel"}, results_key="channels"):
            resources.append(self._create_channel_resource(channel))

        # Try to get private channels
        try:
            for channel in self._paginate("conversations.list", params={"types": "private_channel"}, results_key="channels"):
                resources.append(self._create_channel_resource(channel))
        except requests.RequestException:
            pass

        return resources

    def _create_channel_resource(self, channel: dict[str, Any]) -> Resource:
        """Create a channel resource."""
        return Resource(
            id=str(channel.get("id", "")),
            type="slack_channel",
            provider="slack",
            region="global",
            name=channel.get("name", "Unknown"),
            tags={
                "is_private": str(channel.get("is_private", False)).lower(),
                "is_archived": str(channel.get("is_archived", False)).lower(),
                "is_shared": str(channel.get("is_shared", False) or channel.get("is_ext_shared", False)).lower(),
            },
            metadata={
                "id": channel.get("id"),
                "name": channel.get("name"),
                "is_private": channel.get("is_private", False),
                "is_archived": channel.get("is_archived", False),
                "is_general": channel.get("is_general", False),
                "is_shared": channel.get("is_shared", False),
                "is_ext_shared": channel.get("is_ext_shared", False),
                "creator": channel.get("creator"),
                "created": channel.get("created"),
                "num_members": channel.get("num_members", 0),
            },
            raw_data=channel,
        )

    def _collect_user_group_resources(self) -> list[Resource]:
        """Collect user group resources."""
        logger.info("Collecting Slack user group resources...")
        resources = []

        try:
            data = self._make_request("usergroups.list", params={"include_count": "true"})
            for group in data.get("usergroups", []):
                resources.append(
                    Resource(
                        id=str(group.get("id", "")),
                        type="slack_user_group",
                        provider="slack",
                        region="global",
                        name=group.get("name", "Unknown"),
                        tags={
                            "handle": group.get("handle", ""),
                            "is_external": str(group.get("is_external", False)).lower(),
                        },
                        metadata={
                            "id": group.get("id"),
                            "name": group.get("name"),
                            "handle": group.get("handle"),
                            "description": group.get("description"),
                            "is_external": group.get("is_external", False),
                            "user_count": group.get("user_count", 0),
                        },
                        raw_data=group,
                    )
                )
        except requests.RequestException as e:
            logger.warning(f"Error collecting user group resources: {e}")

        return resources

    def _collect_app_resources(self) -> list[Resource]:
        """Collect app resources."""
        logger.info("Collecting Slack app resources...")
        resources = []

        # Get bot users as proxy for apps
        try:
            for user in self._paginate("users.list", results_key="members"):
                if user.get("is_bot") or user.get("is_app_user"):
                    resources.append(
                        Resource(
                            id=str(user.get("id", "")),
                            type="slack_app",
                            provider="slack",
                            region="global",
                            name=user.get("real_name") or user.get("name", "Unknown"),
                            tags={
                                "is_bot": str(user.get("is_bot", False)).lower(),
                                "is_app_user": str(user.get("is_app_user", False)).lower(),
                            },
                            metadata={
                                "id": user.get("id"),
                                "name": user.get("name"),
                                "real_name": user.get("real_name"),
                                "is_bot": user.get("is_bot", False),
                                "is_app_user": user.get("is_app_user", False),
                            },
                            raw_data=user,
                        )
                    )
        except requests.RequestException as e:
            logger.warning(f"Error collecting app resources: {e}")

        return resources
