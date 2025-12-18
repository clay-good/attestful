"""
1Password collector for Attestful.

Collects password management, secrets, and access evidence from 1Password
for compliance frameworks including SOC 2, NIST 800-53, ISO 27001, and HITRUST.
"""

from __future__ import annotations

from dataclasses import dataclass
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
class OnePasswordCollectorConfig:
    """Configuration for 1Password collector."""

    # 1Password Connect Server URL (for 1Password Connect API)
    connect_url: str = ""

    # Connect Server Token
    connect_token: str = ""

    # SCIM Bridge URL (alternative for user/group management)
    scim_url: str = ""

    # SCIM Bearer Token
    scim_token: str = ""

    # Events API Token (for audit events)
    events_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90


class OnePasswordCollector(BaseCollector):
    """
    1Password collector for password management and secrets evidence.

    Collects evidence related to:
    - Users and their access levels
    - Groups and team memberships
    - Vaults and their configurations
    - Items (passwords, secrets, etc.) metadata
    - Audit events and activity logs

    Evidence Types:
    - users: 1Password users with access levels
    - groups: Groups and team memberships
    - vaults: Vaults and access configurations
    - items: Items metadata (passwords, secrets, etc.)
    - audit_events: Activity and security events

    Resource Types:
    - onepassword_user: User resources
    - onepassword_group: Group resources
    - onepassword_vault: Vault resources

    Supports multiple APIs:
    - 1Password Connect API: For programmatic access to vaults and items
    - 1Password SCIM Bridge: For user and group provisioning
    - 1Password Events API: For audit logs and activity tracking

    Example:
        collector = OnePasswordCollector(
            config=OnePasswordCollectorConfig(
                connect_url="https://connect.company.com",
                connect_token="your-connect-token",
                events_token="your-events-token",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "vaults", "audit_events"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["onepassword_user", "onepassword_vault"]
        )
    """

    PLATFORM = "onepassword"

    metadata = CollectorMetadata(
        name="OnePasswordCollector",
        platform="onepassword",
        description="Collects password management and secrets evidence from 1Password",
        mode=CollectorMode.BOTH,
        resource_types=[
            "onepassword_user",
            "onepassword_group",
            "onepassword_vault",
        ],
        evidence_types=[
            "users",
            "groups",
            "vaults",
            "items",
            "audit_events",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "onepassword_user",
        "onepassword_group",
        "onepassword_vault",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "groups",
        "vaults",
        "items",
        "audit_events",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2", "IA-4", "IA-5"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3", "A.9.4.3"],
            "hitrust": ["01.b", "01.c", "01.d", "01.q"],
        },
        "groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.c", "01.d"],
        },
        "vaults": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["AC-3", "AC-6", "SC-12", "SC-28"],
            "iso_27001": ["A.9.1.2", "A.9.4.1", "A.10.1.2"],
            "hitrust": ["01.c", "06.d", "09.y"],
        },
        "items": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["IA-5", "SC-12", "SC-13", "SC-28"],
            "iso_27001": ["A.9.4.3", "A.10.1.1", "A.10.1.2"],
            "hitrust": ["01.q", "06.d", "09.y"],
        },
        "audit_events": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    def __init__(self, config: OnePasswordCollectorConfig | None = None):
        """Initialize the 1Password collector."""
        self.config = config or OnePasswordCollectorConfig()
        self._connect_session: requests.Session | None = None
        self._scim_session: requests.Session | None = None
        self._events_session: requests.Session | None = None

    def _create_session(self, token: str) -> requests.Session:
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
        session.headers["Authorization"] = f"Bearer {token}"
        session.headers["Content-Type"] = "application/json"

        return session

    @property
    def connect_session(self) -> requests.Session:
        """Get or create a Connect API session."""
        if self._connect_session is None:
            if not self.config.connect_token:
                raise ConfigurationError("1Password Connect token not configured")
            self._connect_session = self._create_session(self.config.connect_token)
        return self._connect_session

    @property
    def scim_session(self) -> requests.Session:
        """Get or create a SCIM API session."""
        if self._scim_session is None:
            if not self.config.scim_token:
                raise ConfigurationError("1Password SCIM token not configured")
            self._scim_session = self._create_session(self.config.scim_token)
        return self._scim_session

    @property
    def events_session(self) -> requests.Session:
        """Get or create an Events API session."""
        if self._events_session is None:
            if not self.config.events_token:
                raise ConfigurationError("1Password Events API token not configured")
            self._events_session = self._create_session(self.config.events_token)
        return self._events_session

    def _make_connect_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a request to the Connect API."""
        if not self.config.connect_url:
            raise ConfigurationError("1Password Connect URL not configured")

        url = f"{self.config.connect_url.rstrip('/')}/v1/{endpoint.lstrip('/')}"

        try:
            response = self.connect_session.request(
                method,
                url,
                params=params,
                json=json_data,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.RequestException as e:
            logger.warning(f"Connect API request failed: {endpoint} - {e}")
            raise

    def _make_scim_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a request to the SCIM API."""
        if not self.config.scim_url:
            raise ConfigurationError("1Password SCIM URL not configured")

        url = f"{self.config.scim_url.rstrip('/')}/{endpoint.lstrip('/')}"

        try:
            response = self.scim_session.request(
                method,
                url,
                params=params,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.RequestException as e:
            logger.warning(f"SCIM API request failed: {endpoint} - {e}")
            raise

    def _make_events_request(
        self,
        endpoint: str,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a request to the Events API."""
        # Events API is always at events.1password.com
        url = f"https://events.1password.com/api/v1/{endpoint.lstrip('/')}"

        try:
            response = self.events_session.post(
                url,
                json=json_data or {},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.RequestException as e:
            logger.warning(f"Events API request failed: {endpoint} - {e}")
            raise

    def _paginate_scim(
        self,
        endpoint: str,
        results_key: str = "Resources",
    ) -> Iterator[dict[str, Any]]:
        """Paginate through SCIM API results."""
        start_index = 1

        while True:
            params = {
                "startIndex": start_index,
                "count": self.config.page_size,
            }

            try:
                data = self._make_scim_request("GET", endpoint, params=params)
                items = data.get(results_key, [])

                for item in items:
                    yield item

                # Check if more results
                total_results = data.get("totalResults", 0)
                items_per_page = data.get("itemsPerPage", len(items))
                if start_index + items_per_page > total_results:
                    break

                start_index += items_per_page

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate 1Password credentials."""
        # Try Connect API
        if self.config.connect_url and self.config.connect_token:
            try:
                self._make_connect_request("GET", "vaults")
                logger.info("1Password Connect API credentials validated")
                return True
            except Exception as e:
                logger.warning(f"Connect API validation failed: {e}")

        # Try SCIM API
        if self.config.scim_url and self.config.scim_token:
            try:
                self._make_scim_request("GET", "Users", params={"count": 1})
                logger.info("1Password SCIM API credentials validated")
                return True
            except Exception as e:
                logger.warning(f"SCIM API validation failed: {e}")

        # Try Events API
        if self.config.events_token:
            try:
                self._make_events_request("auditevents", {"limit": 1})
                logger.info("1Password Events API credentials validated")
                return True
            except Exception as e:
                logger.warning(f"Events API validation failed: {e}")

        raise ConfigurationError(
            "No valid 1Password credentials configured. "
            "Please provide Connect, SCIM, or Events API credentials."
        )

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from 1Password."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting 1Password evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "groups": self._collect_groups_evidence,
            "vaults": self._collect_vaults_evidence,
            "items": self._collect_items_evidence,
            "audit_events": self._collect_audit_events_evidence,
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
        logger.info("Collecting 1Password users...")
        users = []

        # Try SCIM API first (preferred for user management)
        if self.config.scim_url and self.config.scim_token:
            try:
                for user in self._paginate_scim("Users"):
                    users.append(self._normalize_scim_user(user))
            except Exception as e:
                logger.warning(f"SCIM user collection failed: {e}")

        # If no users collected, note the limitation
        if not users:
            logger.info("No users collected - SCIM API may not be configured")

        # Calculate statistics
        active_count = sum(1 for u in users if u.get("active", False))
        admin_count = sum(1 for u in users if u.get("is_admin", False))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "active_count": active_count,
                "admin_count": admin_count,
                "inactive_count": len(users) - active_count,
            },
            metadata={
                "source": "collector:onepassword",
                "api": "scim" if users else "none",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _normalize_scim_user(self, user: dict[str, Any]) -> dict[str, Any]:
        """Normalize SCIM user data."""
        emails = user.get("emails", [])
        primary_email = None
        for email in emails:
            if email.get("primary"):
                primary_email = email.get("value")
                break
        if not primary_email and emails:
            primary_email = emails[0].get("value")

        # Check for admin role
        is_admin = False
        roles = user.get("roles", [])
        for role in roles:
            if role.get("value", "").lower() in ["admin", "owner"]:
                is_admin = True
                break

        return {
            "id": user.get("id"),
            "external_id": user.get("externalId"),
            "user_name": user.get("userName"),
            "email": primary_email,
            "name": user.get("displayName") or user.get("name", {}).get("formatted"),
            "active": user.get("active", False),
            "is_admin": is_admin,
            "roles": [r.get("value") for r in roles],
            "created": user.get("meta", {}).get("created"),
            "last_modified": user.get("meta", {}).get("lastModified"),
        }

    def _collect_groups_evidence(self) -> Evidence:
        """Collect groups evidence."""
        logger.info("Collecting 1Password groups...")
        groups = []

        # Try SCIM API
        if self.config.scim_url and self.config.scim_token:
            try:
                for group in self._paginate_scim("Groups"):
                    groups.append(self._normalize_scim_group(group))
            except Exception as e:
                logger.warning(f"SCIM group collection failed: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": groups,
                "total_count": len(groups),
            },
            metadata={
                "source": "collector:onepassword",
                "api": "scim" if groups else "none",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["groups"],
            },
        )

    def _normalize_scim_group(self, group: dict[str, Any]) -> dict[str, Any]:
        """Normalize SCIM group data."""
        members = group.get("members", [])

        return {
            "id": group.get("id"),
            "external_id": group.get("externalId"),
            "display_name": group.get("displayName"),
            "member_count": len(members),
            "members": [
                {
                    "id": m.get("value"),
                    "display": m.get("display"),
                }
                for m in members
            ],
            "created": group.get("meta", {}).get("created"),
            "last_modified": group.get("meta", {}).get("lastModified"),
        }

    def _collect_vaults_evidence(self) -> Evidence:
        """Collect vaults evidence."""
        logger.info("Collecting 1Password vaults...")
        vaults = []

        # Try Connect API
        if self.config.connect_url and self.config.connect_token:
            try:
                data = self._make_connect_request("GET", "vaults")
                for vault in data if isinstance(data, list) else data.get("vaults", []):
                    vaults.append(self._normalize_vault(vault))
            except Exception as e:
                logger.warning(f"Connect vault collection failed: {e}")

        # Calculate statistics
        shared_count = sum(1 for v in vaults if v.get("type") == "USER_CREATED")
        private_count = sum(1 for v in vaults if v.get("type") == "PERSONAL")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="vaults",
            raw_data={
                "vaults": vaults,
                "total_count": len(vaults),
                "shared_count": shared_count,
                "private_count": private_count,
            },
            metadata={
                "source": "collector:onepassword",
                "api": "connect" if vaults else "none",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["vaults"],
            },
        )

    def _normalize_vault(self, vault: dict[str, Any]) -> dict[str, Any]:
        """Normalize vault data."""
        return {
            "id": vault.get("id"),
            "name": vault.get("name"),
            "description": vault.get("description"),
            "type": vault.get("type"),
            "attribute_version": vault.get("attributeVersion"),
            "content_version": vault.get("contentVersion"),
            "items": vault.get("items"),
            "created_at": vault.get("createdAt"),
            "updated_at": vault.get("updatedAt"),
        }

    def _collect_items_evidence(self) -> Evidence:
        """Collect items metadata evidence (not secrets themselves)."""
        logger.info("Collecting 1Password items metadata...")
        items_summary = []
        total_items = 0
        items_by_category: dict[str, int] = {}
        items_by_vault: dict[str, int] = {}

        # Try Connect API - get items metadata only (not secrets)
        if self.config.connect_url and self.config.connect_token:
            try:
                # First get all vaults
                vaults_data = self._make_connect_request("GET", "vaults")
                vaults = vaults_data if isinstance(vaults_data, list) else vaults_data.get("vaults", [])

                for vault in vaults:
                    vault_id = vault.get("id")
                    vault_name = vault.get("name", "Unknown")

                    try:
                        # Get items in vault (metadata only)
                        items_data = self._make_connect_request("GET", f"vaults/{vault_id}/items")
                        items = items_data if isinstance(items_data, list) else items_data.get("items", [])

                        items_by_vault[vault_name] = len(items)
                        total_items += len(items)

                        for item in items:
                            category = item.get("category", "UNKNOWN")
                            items_by_category[category] = items_by_category.get(category, 0) + 1

                            items_summary.append({
                                "id": item.get("id"),
                                "vault_id": vault_id,
                                "vault_name": vault_name,
                                "title": item.get("title"),
                                "category": category,
                                "tags": item.get("tags", []),
                                "created_at": item.get("createdAt"),
                                "updated_at": item.get("updatedAt"),
                                "last_edited_by": item.get("lastEditedBy"),
                                "favorite": item.get("favorite", False),
                            })

                    except Exception as e:
                        logger.warning(f"Failed to get items for vault {vault_name}: {e}")

            except Exception as e:
                logger.warning(f"Connect items collection failed: {e}")

        # Identify potential security concerns
        old_items = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=365)
        for item in items_summary:
            updated_at = item.get("updated_at")
            if updated_at:
                try:
                    updated_date = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                    if updated_date < cutoff:
                        old_items.append(item)
                except (ValueError, TypeError):
                    pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="items",
            raw_data={
                "items": items_summary,
                "total_count": total_items,
                "items_by_category": items_by_category,
                "items_by_vault": items_by_vault,
                "old_items_count": len(old_items),
                "note": "Only metadata collected, no secrets or passwords",
            },
            metadata={
                "source": "collector:onepassword",
                "api": "connect" if items_summary else "none",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["items"],
            },
        )

    def _collect_audit_events_evidence(self) -> Evidence:
        """Collect audit events evidence."""
        logger.info("Collecting 1Password audit events...")
        events = []
        event_types: dict[str, int] = {}

        # Try Events API
        if self.config.events_token:
            try:
                # Calculate date range
                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(days=self.config.days_of_history)

                # Request audit events
                request_data = {
                    "limit": 1000,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                }

                data = self._make_events_request("auditevents", request_data)

                for event in data.get("items", []):
                    event_type = event.get("action", "unknown")
                    event_types[event_type] = event_types.get(event_type, 0) + 1

                    events.append({
                        "uuid": event.get("uuid"),
                        "timestamp": event.get("timestamp"),
                        "action": event_type,
                        "object_type": event.get("object_type"),
                        "object_uuid": event.get("object_uuid"),
                        "actor_uuid": event.get("actor_uuid"),
                        "actor_details": event.get("actor_details", {}),
                        "aux_id": event.get("aux_id"),
                        "aux_uuid": event.get("aux_uuid"),
                        "aux_info": event.get("aux_info"),
                        "session": event.get("session", {}),
                        "location": event.get("location", {}),
                    })

                # Handle pagination with cursor
                cursor = data.get("cursor")
                while cursor and len(events) < 10000:  # Limit total events
                    request_data["cursor"] = cursor
                    data = self._make_events_request("auditevents", request_data)

                    for event in data.get("items", []):
                        event_type = event.get("action", "unknown")
                        event_types[event_type] = event_types.get(event_type, 0) + 1
                        events.append({
                            "uuid": event.get("uuid"),
                            "timestamp": event.get("timestamp"),
                            "action": event_type,
                            "object_type": event.get("object_type"),
                            "object_uuid": event.get("object_uuid"),
                            "actor_uuid": event.get("actor_uuid"),
                            "actor_details": event.get("actor_details", {}),
                            "aux_id": event.get("aux_id"),
                            "aux_uuid": event.get("aux_uuid"),
                            "aux_info": event.get("aux_info"),
                            "session": event.get("session", {}),
                            "location": event.get("location", {}),
                        })

                    cursor = data.get("cursor")
                    if not data.get("items"):
                        break

            except Exception as e:
                logger.warning(f"Events API collection failed: {e}")

        # Identify security-relevant events
        security_actions = [
            "signin", "signout", "mfa_", "password", "vault_", "user_",
            "group_", "invite", "suspend", "reactivate", "delete",
        ]
        security_events = [
            e for e in events
            if any(sa in e.get("action", "").lower() for sa in security_actions)
        ]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_events",
            raw_data={
                "events": events,
                "total_count": len(events),
                "event_types": event_types,
                "security_events_count": len(security_events),
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:onepassword",
                "api": "events" if events else "none",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_events"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from 1Password for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting 1Password resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "onepassword_user": self._collect_user_resources,
            "onepassword_group": self._collect_group_resources,
            "onepassword_vault": self._collect_vault_resources,
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
        logger.info("Collecting 1Password user resources...")
        resources = []

        if self.config.scim_url and self.config.scim_token:
            try:
                for user in self._paginate_scim("Users"):
                    normalized = self._normalize_scim_user(user)

                    # Determine user role
                    if normalized.get("is_admin"):
                        role = "admin"
                    elif normalized.get("active"):
                        role = "member"
                    else:
                        role = "suspended"

                    resources.append(
                        Resource(
                            id=str(normalized.get("id", "")),
                            type="onepassword_user",
                            provider="onepassword",
                            region="global",
                            name=normalized.get("name") or normalized.get("email") or "Unknown",
                            tags={
                                "role": role,
                                "active": str(normalized.get("active", False)).lower(),
                                "is_admin": str(normalized.get("is_admin", False)).lower(),
                            },
                            metadata={
                                "id": normalized.get("id"),
                                "user_name": normalized.get("user_name"),
                                "email": normalized.get("email"),
                                "active": normalized.get("active"),
                                "is_admin": normalized.get("is_admin"),
                                "roles": normalized.get("roles", []),
                            },
                            raw_data=user,
                        )
                    )
            except Exception as e:
                logger.warning(f"User resource collection failed: {e}")

        return resources

    def _collect_group_resources(self) -> list[Resource]:
        """Collect group resources."""
        logger.info("Collecting 1Password group resources...")
        resources = []

        if self.config.scim_url and self.config.scim_token:
            try:
                for group in self._paginate_scim("Groups"):
                    normalized = self._normalize_scim_group(group)

                    resources.append(
                        Resource(
                            id=str(normalized.get("id", "")),
                            type="onepassword_group",
                            provider="onepassword",
                            region="global",
                            name=normalized.get("display_name") or "Unknown",
                            tags={
                                "member_count": str(normalized.get("member_count", 0)),
                            },
                            metadata={
                                "id": normalized.get("id"),
                                "display_name": normalized.get("display_name"),
                                "member_count": normalized.get("member_count"),
                            },
                            raw_data=group,
                        )
                    )
            except Exception as e:
                logger.warning(f"Group resource collection failed: {e}")

        return resources

    def _collect_vault_resources(self) -> list[Resource]:
        """Collect vault resources."""
        logger.info("Collecting 1Password vault resources...")
        resources = []

        if self.config.connect_url and self.config.connect_token:
            try:
                data = self._make_connect_request("GET", "vaults")
                vaults = data if isinstance(data, list) else data.get("vaults", [])

                for vault in vaults:
                    normalized = self._normalize_vault(vault)

                    # Determine vault type tag
                    vault_type = normalized.get("type", "UNKNOWN")
                    is_shared = vault_type in ["USER_CREATED", "TEAM"]

                    resources.append(
                        Resource(
                            id=str(normalized.get("id", "")),
                            type="onepassword_vault",
                            provider="onepassword",
                            region="global",
                            name=normalized.get("name") or "Unknown",
                            tags={
                                "type": vault_type,
                                "is_shared": str(is_shared).lower(),
                            },
                            metadata={
                                "id": normalized.get("id"),
                                "name": normalized.get("name"),
                                "description": normalized.get("description"),
                                "type": vault_type,
                                "item_count": normalized.get("items"),
                            },
                            raw_data=vault,
                        )
                    )
            except Exception as e:
                logger.warning(f"Vault resource collection failed: {e}")

        return resources
