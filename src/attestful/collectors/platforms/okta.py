"""
Okta collector for Attestful.

Collects identity and access management evidence from Okta
for compliance frameworks including SOC 2, NIST 800-53, and ISO 27001.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from attestful.collectors.base import BaseCollector
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


@dataclass
class OktaCollectorConfig:
    """Configuration for Okta collector."""

    domain: str = ""
    api_token: str = ""
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 200


class OktaCollector(BaseCollector):
    """
    Okta collector for identity and access evidence.

    Collects evidence related to:
    - User accounts and profiles
    - MFA enrollment status
    - Application assignments
    - Group memberships
    - Authentication policies
    - System logs (audit events)

    Evidence Types:
    - users: All Okta users with profile and status
    - mfa_factors: MFA enrollment for all users
    - groups: Groups and their members
    - applications: Applications and user assignments
    - policies: Authentication and password policies
    - system_log: Recent authentication and admin events

    Resource Types:
    - okta_user: Individual user accounts
    - okta_group: Security groups
    - okta_application: Integrated applications

    Example:
        collector = OktaCollector(
            config=OktaCollectorConfig(
                domain="company.okta.com",
                api_token="00abc...",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "mfa_factors", "policies"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["okta_user"]
        )
    """

    PLATFORM = "okta"
    SUPPORTED_RESOURCE_TYPES = [
        "okta_user",
        "okta_group",
        "okta_application",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "mfa_factors",
        "groups",
        "applications",
        "policies",
        "system_log",
    ]

    def __init__(
        self,
        config: OktaCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Okta collector.

        Args:
            config: Okta collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or OktaCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def base_url(self) -> str:
        """Get the Okta API base URL."""
        domain = self.config.domain
        if not domain:
            raise ConfigurationError("Okta domain not configured")
        if not domain.startswith("https://"):
            domain = f"https://{domain}"
        return f"{domain}/api/v1"

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

            # Set headers
            self._session.headers.update({
                "Authorization": f"SSWS {self.config.api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            })

        return self._session

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an API request with rate limiting."""
        self._rate_limit()

        session = self._get_session()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        kwargs.setdefault("timeout", self.config.timeout)

        response = session.request(method, url, **kwargs)

        # Handle rate limiting
        if response.status_code == 429:
            retry_after = int(response.headers.get("X-Rate-Limit-Reset", 60))
            logger.warning(f"Rate limited, waiting {retry_after}s")
            import time
            time.sleep(retry_after)
            return self._request(method, endpoint, **kwargs)

        response.raise_for_status()
        return response

    def _paginate(self, endpoint: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Paginate through API results."""
        params = kwargs.pop("params", {})
        params.setdefault("limit", self.config.page_size)

        while True:
            response = self._request("GET", endpoint, params=params, **kwargs)
            items = response.json()

            for item in items:
                yield item

            # Check for next page
            links = response.headers.get("Link", "")
            next_url = None
            for link in links.split(","):
                if 'rel="next"' in link:
                    next_url = link.split(";")[0].strip("<> ")
                    break

            if not next_url:
                break

            # Extract cursor for next request
            endpoint = next_url.replace(self.base_url, "")
            params = {}  # URL already contains params

    def validate_credentials(self) -> bool:
        """Validate Okta API credentials."""
        try:
            response = self._request("GET", "/users/me")
            user = response.json()
            logger.info(f"Validated Okta credentials for {user.get('profile', {}).get('email')}")
            return True
        except Exception as e:
            logger.error(f"Okta credential validation failed: {e}")
            return False

    # =========================================================================
    # Resource Collection Methods
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """
        Collect Okta resources.

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

    def _collect_okta_user(self) -> Iterator[Resource]:
        """Collect Okta users as resources."""
        for user in self._paginate("/users"):
            yield Resource(
                id=user["id"],
                type="okta_user",
                provider="okta",
                region="global",
                name=user.get("profile", {}).get("email", user["id"]),
                tags={
                    "status": user.get("status", ""),
                    "type": user.get("type", {}).get("id", ""),
                },
                raw_data=user,
            )

    def _collect_okta_group(self) -> Iterator[Resource]:
        """Collect Okta groups as resources."""
        for group in self._paginate("/groups"):
            yield Resource(
                id=group["id"],
                type="okta_group",
                provider="okta",
                region="global",
                name=group.get("profile", {}).get("name", group["id"]),
                tags={
                    "type": group.get("type", ""),
                },
                raw_data=group,
            )

    def _collect_okta_application(self) -> Iterator[Resource]:
        """Collect Okta applications as resources."""
        for app in self._paginate("/apps"):
            yield Resource(
                id=app["id"],
                type="okta_application",
                provider="okta",
                region="global",
                name=app.get("label", app["id"]),
                tags={
                    "status": app.get("status", ""),
                    "sign_on_mode": app.get("signOnMode", ""),
                },
                raw_data=app,
            )

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect Okta evidence for compliance audits.

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
        """Collect all Okta users with profile information."""
        users = list(self._paginate("/users"))

        # Summarize user data
        status_counts: dict[str, int] = {}
        for user in users:
            status = user.get("status", "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "status_breakdown": status_counts,
            },
            metadata={
                "source": "collector:okta",
                "collection_method": "automated",
            },
        )

    def _evidence_mfa_factors(self) -> Evidence:
        """Collect MFA enrollment status for all users."""
        users = list(self._paginate("/users"))
        mfa_data: list[dict[str, Any]] = []

        for user in users:
            user_id = user["id"]
            email = user.get("profile", {}).get("email", user_id)

            try:
                self._rate_limit()
                response = self._request("GET", f"/users/{user_id}/factors")
                factors = response.json()

                mfa_data.append({
                    "user_id": user_id,
                    "email": email,
                    "status": user.get("status"),
                    "factors": factors,
                    "factor_count": len(factors),
                    "has_mfa": len(factors) > 0,
                    "factor_types": [f.get("factorType") for f in factors],
                })
            except Exception as e:
                logger.warning(f"Failed to get MFA for user {email}: {e}")
                mfa_data.append({
                    "user_id": user_id,
                    "email": email,
                    "status": user.get("status"),
                    "factors": [],
                    "factor_count": 0,
                    "has_mfa": False,
                    "error": str(e),
                })

        # Summary statistics
        total_users = len(mfa_data)
        users_with_mfa = sum(1 for u in mfa_data if u["has_mfa"])
        mfa_rate = (users_with_mfa / total_users * 100) if total_users > 0 else 0

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="mfa_factors",
            raw_data={
                "users": mfa_data,
                "summary": {
                    "total_users": total_users,
                    "users_with_mfa": users_with_mfa,
                    "users_without_mfa": total_users - users_with_mfa,
                    "mfa_enrollment_rate": round(mfa_rate, 2),
                },
            },
            metadata={
                "source": "collector:okta",
                "collection_method": "automated",
            },
        )

    def _evidence_groups(self) -> Evidence:
        """Collect groups and their members."""
        groups = list(self._paginate("/groups"))
        groups_data: list[dict[str, Any]] = []

        for group in groups:
            group_id = group["id"]
            group_name = group.get("profile", {}).get("name", group_id)

            try:
                self._rate_limit()
                members = list(self._paginate(f"/groups/{group_id}/users"))

                groups_data.append({
                    "id": group_id,
                    "name": group_name,
                    "type": group.get("type"),
                    "description": group.get("profile", {}).get("description"),
                    "member_count": len(members),
                    "members": [
                        {
                            "id": m["id"],
                            "email": m.get("profile", {}).get("email"),
                            "status": m.get("status"),
                        }
                        for m in members
                    ],
                })
            except Exception as e:
                logger.warning(f"Failed to get members for group {group_name}: {e}")
                groups_data.append({
                    "id": group_id,
                    "name": group_name,
                    "type": group.get("type"),
                    "member_count": 0,
                    "members": [],
                    "error": str(e),
                })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": groups_data,
                "total_groups": len(groups_data),
            },
            metadata={
                "source": "collector:okta",
                "collection_method": "automated",
            },
        )

    def _evidence_applications(self) -> Evidence:
        """Collect applications and their configurations."""
        apps = list(self._paginate("/apps"))
        apps_data: list[dict[str, Any]] = []

        for app in apps:
            app_id = app["id"]

            # Get assigned users count
            try:
                self._rate_limit()
                users = list(self._paginate(f"/apps/{app_id}/users"))
                user_count = len(users)
            except Exception:
                user_count = 0

            apps_data.append({
                "id": app_id,
                "name": app.get("label"),
                "status": app.get("status"),
                "sign_on_mode": app.get("signOnMode"),
                "visibility": app.get("visibility", {}),
                "features": app.get("features", []),
                "assigned_users_count": user_count,
                "created": app.get("created"),
                "last_updated": app.get("lastUpdated"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="applications",
            raw_data={
                "applications": apps_data,
                "total_applications": len(apps_data),
                "active_applications": sum(1 for a in apps_data if a["status"] == "ACTIVE"),
            },
            metadata={
                "source": "collector:okta",
                "collection_method": "automated",
            },
        )

    def _evidence_policies(self) -> Evidence:
        """Collect authentication and password policies."""
        policies_data: dict[str, Any] = {
            "password_policies": [],
            "sign_on_policies": [],
        }

        # Get password policies
        try:
            self._rate_limit()
            response = self._request("GET", "/policies", params={"type": "PASSWORD"})
            password_policies = response.json()

            for policy in password_policies:
                policy_id = policy["id"]

                # Get policy rules
                try:
                    self._rate_limit()
                    rules_response = self._request("GET", f"/policies/{policy_id}/rules")
                    rules = rules_response.json()
                except Exception:
                    rules = []

                policies_data["password_policies"].append({
                    "id": policy_id,
                    "name": policy.get("name"),
                    "status": policy.get("status"),
                    "description": policy.get("description"),
                    "priority": policy.get("priority"),
                    "conditions": policy.get("conditions", {}),
                    "settings": policy.get("settings", {}),
                    "rules": rules,
                })
        except Exception as e:
            logger.warning(f"Failed to get password policies: {e}")

        # Get sign-on policies
        try:
            self._rate_limit()
            response = self._request("GET", "/policies", params={"type": "OKTA_SIGN_ON"})
            sign_on_policies = response.json()

            for policy in sign_on_policies:
                policy_id = policy["id"]

                try:
                    self._rate_limit()
                    rules_response = self._request("GET", f"/policies/{policy_id}/rules")
                    rules = rules_response.json()
                except Exception:
                    rules = []

                policies_data["sign_on_policies"].append({
                    "id": policy_id,
                    "name": policy.get("name"),
                    "status": policy.get("status"),
                    "description": policy.get("description"),
                    "priority": policy.get("priority"),
                    "conditions": policy.get("conditions", {}),
                    "settings": policy.get("settings", {}),
                    "rules": rules,
                })
        except Exception as e:
            logger.warning(f"Failed to get sign-on policies: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="policies",
            raw_data=policies_data,
            metadata={
                "source": "collector:okta",
                "collection_method": "automated",
            },
        )

    def _evidence_system_log(self) -> Evidence:
        """Collect recent system log events."""
        # Get events from the last 7 days
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

        events: list[dict[str, Any]] = []
        event_types: dict[str, int] = {}

        try:
            for event in self._paginate("/logs", params={"since": since, "limit": 1000}):
                events.append({
                    "uuid": event.get("uuid"),
                    "published": event.get("published"),
                    "event_type": event.get("eventType"),
                    "display_message": event.get("displayMessage"),
                    "severity": event.get("severity"),
                    "outcome": event.get("outcome", {}),
                    "actor": event.get("actor", {}),
                    "target": event.get("target", []),
                    "client": event.get("client", {}),
                })

                event_type = event.get("eventType", "unknown")
                event_types[event_type] = event_types.get(event_type, 0) + 1

                # Limit to most recent 1000 events
                if len(events) >= 1000:
                    break

        except Exception as e:
            logger.warning(f"Failed to get system logs: {e}")

        # Identify security-relevant events
        security_events = [
            e for e in events
            if e.get("severity") in ["WARN", "ERROR"]
            or "security" in e.get("event_type", "").lower()
            or "password" in e.get("event_type", "").lower()
            or "mfa" in e.get("event_type", "").lower()
        ]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="system_log",
            raw_data={
                "events": events,
                "total_events": len(events),
                "event_type_breakdown": event_types,
                "security_events_count": len(security_events),
                "period_start": since,
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:okta",
                "collection_method": "automated",
            },
        )
