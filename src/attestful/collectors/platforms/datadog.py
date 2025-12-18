"""
Datadog collector for Attestful.

Collects monitoring and observability evidence from Datadog
for compliance frameworks including SOC 2, NIST 800-53, and ISO 27001.
"""

from __future__ import annotations

from dataclasses import dataclass
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
class DatadogCollectorConfig:
    """Configuration for Datadog collector."""

    api_key: str = ""
    app_key: str = ""
    site: str = "datadoghq.com"  # or datadoghq.eu, us3.datadoghq.com, etc.
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100
    days_of_history: int = 30


class DatadogCollector(BaseCollector):
    """
    Datadog collector for monitoring and observability evidence.

    Collects evidence related to:
    - Monitors (alerting rules and status)
    - Dashboards (configuration and sharing)
    - Users (access and permissions)
    - API keys (inventory and usage)
    - Audit logs (admin activities)
    - Security monitoring rules
    - Service level objectives (SLOs)
    - Synthetics (uptime monitoring)

    Evidence Types:
    - monitors: All configured monitors with alerting status
    - dashboards: Dashboard configurations and sharing settings
    - users: Users and their roles/permissions
    - api_keys: API and application keys inventory
    - audit_logs: Recent administrative and security events
    - security_rules: Security monitoring detection rules
    - slos: Service level objectives configuration
    - synthetics: Synthetic tests for availability monitoring

    Resource Types:
    - datadog_monitor: Individual monitors
    - datadog_dashboard: Dashboard resources
    - datadog_user: User accounts
    - datadog_slo: Service level objectives

    Compliance Mappings:
    - SOC 2 CC7 (System Operations): Monitors, SLOs, synthetics
    - NIST 800-53 SI-4 (System Monitoring): Security rules, audit logs
    - NIST 800-53 AU-2 (Audit Events): Audit logs
    - ISO 27001 A.12.4 (Event Logging): Audit logs, monitors

    Example:
        collector = DatadogCollector(
            config=DatadogCollectorConfig(
                api_key="your-api-key",
                app_key="your-app-key",
                site="datadoghq.com",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["monitors", "audit_logs", "security_rules"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["datadog_monitor", "datadog_slo"]
        )
    """

    PLATFORM = "datadog"
    SUPPORTED_RESOURCE_TYPES = [
        "datadog_monitor",
        "datadog_dashboard",
        "datadog_user",
        "datadog_slo",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "monitors",
        "dashboards",
        "users",
        "api_keys",
        "audit_logs",
        "security_rules",
        "slos",
        "synthetics",
    ]

    def __init__(
        self,
        config: DatadogCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Datadog collector.

        Args:
            config: Datadog collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or DatadogCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def base_url(self) -> str:
        """Get the Datadog API base URL."""
        site = self.config.site or "datadoghq.com"
        return f"https://api.{site}/api"

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

            # Set headers with API and App keys
            self._session.headers.update({
                "DD-API-KEY": self.config.api_key,
                "DD-APPLICATION-KEY": self.config.app_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            })

        return self._session

    def _request(
        self,
        method: str,
        endpoint: str,
        api_version: str = "v1",
        **kwargs: Any,
    ) -> requests.Response:
        """Make an API request with rate limiting."""
        self._rate_limit()

        session = self._get_session()
        url = f"{self.base_url}/{api_version}/{endpoint.lstrip('/')}"

        kwargs.setdefault("timeout", self.config.timeout)

        response = session.request(method, url, **kwargs)

        # Handle rate limiting
        if response.status_code == 429:
            retry_after = int(response.headers.get("X-RateLimit-Reset", 60))
            logger.warning(f"Rate limited, waiting {retry_after}s")
            import time
            time.sleep(retry_after)
            return self._request(method, endpoint, api_version, **kwargs)

        response.raise_for_status()
        return response

    def _paginate_v2(
        self,
        endpoint: str,
        data_key: str = "data",
        **kwargs: Any,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through API v2 results using cursor-based pagination."""
        params = kwargs.pop("params", {})
        params.setdefault("page[size]", self.config.page_size)

        while True:
            response = self._request("GET", endpoint, api_version="v2", params=params, **kwargs)
            result = response.json()

            items = result.get(data_key, [])
            for item in items:
                yield item

            # Check for next page cursor
            meta = result.get("meta", {})
            page_info = meta.get("page", {})
            next_cursor = page_info.get("after")

            if not next_cursor or not items:
                break

            params["page[cursor]"] = next_cursor

    def validate_credentials(self) -> bool:
        """Validate Datadog API credentials."""
        try:
            response = self._request("GET", "/validate")
            data = response.json()
            if data.get("valid"):
                logger.info("Validated Datadog credentials")
                return True
            logger.error("Datadog credentials invalid")
            return False
        except Exception as e:
            logger.error(f"Datadog credential validation failed: {e}")
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
        Collect Datadog resources.

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

    def _collect_datadog_monitor(self) -> Iterator[Resource]:
        """Collect Datadog monitors as resources."""
        try:
            response = self._request("GET", "/monitor")
            monitors = response.json()

            for monitor in monitors:
                yield Resource(
                    id=str(monitor["id"]),
                    type="datadog_monitor",
                    provider="datadog",
                    region="global",
                    name=monitor.get("name", f"monitor-{monitor['id']}"),
                    tags={
                        "type": monitor.get("type", ""),
                        "overall_state": monitor.get("overall_state", ""),
                        "priority": str(monitor.get("priority", "")),
                    },
                    metadata={
                        "query": monitor.get("query", ""),
                        "message": monitor.get("message", ""),
                        "created": monitor.get("created"),
                        "modified": monitor.get("modified"),
                        "multi": monitor.get("multi", False),
                        "restricted_roles": monitor.get("restricted_roles", []),
                    },
                    raw_data=monitor,
                )
        except Exception as e:
            logger.error(f"Failed to collect monitors: {e}")

    def _collect_datadog_dashboard(self) -> Iterator[Resource]:
        """Collect Datadog dashboards as resources."""
        try:
            response = self._request("GET", "/dashboard")
            data = response.json()
            dashboards = data.get("dashboards", [])

            for dashboard in dashboards:
                yield Resource(
                    id=dashboard["id"],
                    type="datadog_dashboard",
                    provider="datadog",
                    region="global",
                    name=dashboard.get("title", dashboard["id"]),
                    tags={
                        "layout_type": dashboard.get("layout_type", ""),
                        "is_read_only": str(dashboard.get("is_read_only", False)),
                    },
                    metadata={
                        "description": dashboard.get("description", ""),
                        "author_handle": dashboard.get("author_handle", ""),
                        "created_at": dashboard.get("created_at"),
                        "modified_at": dashboard.get("modified_at"),
                        "url": dashboard.get("url", ""),
                    },
                    raw_data=dashboard,
                )
        except Exception as e:
            logger.error(f"Failed to collect dashboards: {e}")

    def _collect_datadog_user(self) -> Iterator[Resource]:
        """Collect Datadog users as resources."""
        try:
            for user in self._paginate_v2("/users"):
                attributes = user.get("attributes", {})
                yield Resource(
                    id=user["id"],
                    type="datadog_user",
                    provider="datadog",
                    region="global",
                    name=attributes.get("email", user["id"]),
                    tags={
                        "status": attributes.get("status", ""),
                        "disabled": str(attributes.get("disabled", False)),
                        "verified": str(attributes.get("verified", False)),
                    },
                    metadata={
                        "name": attributes.get("name", ""),
                        "title": attributes.get("title", ""),
                        "created_at": attributes.get("created_at"),
                        "modified_at": attributes.get("modified_at"),
                        "service_account": attributes.get("service_account", False),
                    },
                    raw_data=user,
                )
        except Exception as e:
            logger.error(f"Failed to collect users: {e}")

    def _collect_datadog_slo(self) -> Iterator[Resource]:
        """Collect Datadog SLOs as resources."""
        try:
            response = self._request("GET", "/slo")
            data = response.json()
            slos = data.get("data", [])

            for slo in slos:
                yield Resource(
                    id=slo["id"],
                    type="datadog_slo",
                    provider="datadog",
                    region="global",
                    name=slo.get("name", slo["id"]),
                    tags={
                        "type": slo.get("type", ""),
                    },
                    metadata={
                        "description": slo.get("description", ""),
                        "target_threshold": slo.get("target_threshold"),
                        "timeframe": slo.get("timeframe", ""),
                        "created_at": slo.get("created_at"),
                        "modified_at": slo.get("modified_at"),
                    },
                    raw_data=slo,
                )
        except Exception as e:
            logger.error(f"Failed to collect SLOs: {e}")

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect Datadog evidence for compliance audits.

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

    def _evidence_monitors(self) -> Evidence:
        """Collect all Datadog monitors with alerting status."""
        try:
            response = self._request("GET", "/monitor")
            monitors = response.json()
        except Exception as e:
            logger.error(f"Failed to get monitors: {e}")
            monitors = []

        # Summarize monitor data
        status_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        critical_monitors: list[dict[str, Any]] = []

        for monitor in monitors:
            state = monitor.get("overall_state", "Unknown")
            status_counts[state] = status_counts.get(state, 0) + 1

            mon_type = monitor.get("type", "unknown")
            type_counts[mon_type] = type_counts.get(mon_type, 0) + 1

            # Track monitors in alert state
            if state in ["Alert", "Warn"]:
                critical_monitors.append({
                    "id": monitor["id"],
                    "name": monitor.get("name"),
                    "type": mon_type,
                    "state": state,
                    "priority": monitor.get("priority"),
                    "tags": monitor.get("tags", []),
                })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="monitors",
            raw_data={
                "monitors": monitors,
                "total_count": len(monitors),
                "status_breakdown": status_counts,
                "type_breakdown": type_counts,
                "monitors_in_alert": critical_monitors,
                "alerts_count": len(critical_monitors),
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.1", "NIST:SI-4", "ISO27001:A.12.4"],
            },
        )

    def _evidence_dashboards(self) -> Evidence:
        """Collect dashboard configurations and sharing settings."""
        try:
            response = self._request("GET", "/dashboard")
            data = response.json()
            dashboards = data.get("dashboards", [])
        except Exception as e:
            logger.error(f"Failed to get dashboards: {e}")
            dashboards = []

        # Analyze dashboards
        dashboard_data: list[dict[str, Any]] = []
        shared_dashboards: list[dict[str, Any]] = []

        for dashboard in dashboards:
            dash_info = {
                "id": dashboard["id"],
                "title": dashboard.get("title"),
                "description": dashboard.get("description", ""),
                "layout_type": dashboard.get("layout_type"),
                "is_read_only": dashboard.get("is_read_only", False),
                "author_handle": dashboard.get("author_handle"),
                "created_at": dashboard.get("created_at"),
                "modified_at": dashboard.get("modified_at"),
                "url": dashboard.get("url", ""),
            }
            dashboard_data.append(dash_info)

            # Track shared dashboards (potential data exposure)
            if dashboard.get("is_read_only") is False:
                shared_dashboards.append(dash_info)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="dashboards",
            raw_data={
                "dashboards": dashboard_data,
                "total_count": len(dashboard_data),
                "shared_dashboards": shared_dashboards,
                "shared_count": len(shared_dashboards),
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
            },
        )

    def _evidence_users(self) -> Evidence:
        """Collect users and their roles/permissions."""
        users_data: list[dict[str, Any]] = []
        role_counts: dict[str, int] = {}

        try:
            for user in self._paginate_v2("/users"):
                attributes = user.get("attributes", {})
                relationships = user.get("relationships", {})

                # Get user roles
                roles = relationships.get("roles", {}).get("data", [])
                role_ids = [r.get("id", "") for r in roles]

                user_info = {
                    "id": user["id"],
                    "email": attributes.get("email"),
                    "name": attributes.get("name"),
                    "status": attributes.get("status"),
                    "disabled": attributes.get("disabled", False),
                    "verified": attributes.get("verified", False),
                    "service_account": attributes.get("service_account", False),
                    "created_at": attributes.get("created_at"),
                    "modified_at": attributes.get("modified_at"),
                    "role_ids": role_ids,
                    "mfa_enabled": attributes.get("mfa_enabled"),
                }
                users_data.append(user_info)

                # Count by status
                status = attributes.get("status", "unknown")
                role_counts[status] = role_counts.get(status, 0) + 1
        except Exception as e:
            logger.error(f"Failed to get users: {e}")

        # Summary statistics
        total_users = len(users_data)
        active_users = sum(1 for u in users_data if u.get("status") == "Active")
        service_accounts = sum(1 for u in users_data if u.get("service_account"))
        disabled_users = sum(1 for u in users_data if u.get("disabled"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users_data,
                "total_count": total_users,
                "status_breakdown": role_counts,
                "summary": {
                    "total_users": total_users,
                    "active_users": active_users,
                    "disabled_users": disabled_users,
                    "service_accounts": service_accounts,
                },
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC6.1", "NIST:AC-2", "ISO27001:A.9.2"],
            },
        )

    def _evidence_api_keys(self) -> Evidence:
        """Collect API and application keys inventory."""
        api_keys_data: list[dict[str, Any]] = []
        app_keys_data: list[dict[str, Any]] = []

        # Get API keys
        try:
            for key in self._paginate_v2("/api_keys"):
                attributes = key.get("attributes", {})
                api_keys_data.append({
                    "id": key["id"],
                    "name": attributes.get("name"),
                    "created_at": attributes.get("created_at"),
                    "modified_at": attributes.get("modified_at"),
                    "last_used_at": attributes.get("last_used_at"),
                    # Never include the actual key value
                    "key_prefix": attributes.get("key", "")[:8] + "..." if attributes.get("key") else None,
                })
        except Exception as e:
            logger.warning(f"Failed to get API keys: {e}")

        # Get application keys
        try:
            for key in self._paginate_v2("/application_keys"):
                attributes = key.get("attributes", {})
                app_keys_data.append({
                    "id": key["id"],
                    "name": attributes.get("name"),
                    "created_at": attributes.get("created_at"),
                    "last_used_at": attributes.get("last_used_at"),
                    "owner": key.get("relationships", {}).get("owned_by", {}).get("data", {}).get("id"),
                    "scopes": attributes.get("scopes", []),
                })
        except Exception as e:
            logger.warning(f"Failed to get application keys: {e}")

        # Identify stale keys (not used in 90 days)
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=90)
        stale_api_keys = []
        stale_app_keys = []

        for key in api_keys_data:
            last_used = key.get("last_used_at")
            if last_used:
                try:
                    last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                    if last_used_dt < stale_threshold:
                        stale_api_keys.append(key)
                except (ValueError, TypeError):
                    pass

        for key in app_keys_data:
            last_used = key.get("last_used_at")
            if last_used:
                try:
                    last_used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                    if last_used_dt < stale_threshold:
                        stale_app_keys.append(key)
                except (ValueError, TypeError):
                    pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="api_keys",
            raw_data={
                "api_keys": api_keys_data,
                "application_keys": app_keys_data,
                "summary": {
                    "total_api_keys": len(api_keys_data),
                    "total_app_keys": len(app_keys_data),
                    "stale_api_keys": len(stale_api_keys),
                    "stale_app_keys": len(stale_app_keys),
                },
                "stale_keys": {
                    "api_keys": stale_api_keys,
                    "app_keys": stale_app_keys,
                    "threshold_days": 90,
                },
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC6.3", "NIST:IA-5", "ISO27001:A.9.4"],
            },
        )

    def _evidence_audit_logs(self) -> Evidence:
        """Collect recent audit log events."""
        # Get events from the configured history window
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        events: list[dict[str, Any]] = []
        event_types: dict[str, int] = {}
        security_events: list[dict[str, Any]] = []

        try:
            params = {
                "filter[from]": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "filter[to]": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "page[limit]": 100,
            }

            for event in self._paginate_v2("/audit/events", params=params):
                attributes = event.get("attributes", {})

                event_data = {
                    "id": event["id"],
                    "timestamp": attributes.get("timestamp"),
                    "type": attributes.get("type", {}).get("name"),
                    "category": attributes.get("type", {}).get("category"),
                    "message": attributes.get("attributes", {}).get("message"),
                    "actor": {
                        "type": attributes.get("actor", {}).get("type"),
                        "id": attributes.get("actor", {}).get("id"),
                        "name": attributes.get("actor", {}).get("name"),
                    },
                    "target": attributes.get("target"),
                    "outcome": attributes.get("outcome"),
                    "service": attributes.get("service"),
                }
                events.append(event_data)

                # Count by event type
                event_type = event_data.get("type", "unknown")
                event_types[event_type] = event_types.get(event_type, 0) + 1

                # Identify security-relevant events
                category = event_data.get("category", "").lower()
                event_type_lower = (event_type or "").lower()
                if any(kw in category or kw in event_type_lower for kw in
                       ["security", "authentication", "access", "permission", "role", "api_key", "password"]):
                    security_events.append(event_data)

                # Limit to most recent 1000 events
                if len(events) >= 1000:
                    break

        except Exception as e:
            logger.warning(f"Failed to get audit logs: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_logs",
            raw_data={
                "events": events,
                "total_events": len(events),
                "event_type_breakdown": event_types,
                "security_events": security_events,
                "security_events_count": len(security_events),
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.2", "NIST:AU-2", "ISO27001:A.12.4"],
            },
        )

    def _evidence_security_rules(self) -> Evidence:
        """Collect security monitoring detection rules."""
        rules_data: list[dict[str, Any]] = []
        enabled_count = 0
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}

        try:
            for rule in self._paginate_v2("/security_monitoring/rules"):
                attributes = rule.get("attributes", {})

                rule_info = {
                    "id": rule["id"],
                    "name": attributes.get("name"),
                    "type": attributes.get("type"),
                    "is_enabled": attributes.get("isEnabled", False),
                    "is_default": attributes.get("isDefault", False),
                    "message": attributes.get("message", ""),
                    "tags": attributes.get("tags", []),
                    "cases": len(attributes.get("cases", [])),
                    "queries": len(attributes.get("queries", [])),
                    "options": attributes.get("options", {}),
                    "created_at": attributes.get("createdAt"),
                    "update_author": attributes.get("updateAuthor"),
                }
                rules_data.append(rule_info)

                if rule_info["is_enabled"]:
                    enabled_count += 1

                rule_type = rule_info.get("type", "unknown")
                by_type[rule_type] = by_type.get(rule_type, 0) + 1

                # Extract severity from cases
                for case in attributes.get("cases", []):
                    severity = case.get("status", "unknown")
                    by_severity[severity] = by_severity.get(severity, 0) + 1

        except Exception as e:
            logger.warning(f"Failed to get security rules: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_rules",
            raw_data={
                "rules": rules_data,
                "total_rules": len(rules_data),
                "enabled_rules": enabled_count,
                "disabled_rules": len(rules_data) - enabled_count,
                "by_type": by_type,
                "by_severity": by_severity,
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.1", "NIST:SI-4", "ISO27001:A.12.6"],
            },
        )

    def _evidence_slos(self) -> Evidence:
        """Collect Service Level Objectives configuration."""
        slos_data: list[dict[str, Any]] = []
        by_type: dict[str, int] = {}
        by_timeframe: dict[str, int] = {}
        slos_met: list[dict[str, Any]] = []
        slos_breached: list[dict[str, Any]] = []

        try:
            response = self._request("GET", "/slo")
            data = response.json()
            slos = data.get("data", [])

            for slo in slos:
                slo_info = {
                    "id": slo["id"],
                    "name": slo.get("name"),
                    "description": slo.get("description", ""),
                    "type": slo.get("type"),
                    "target_threshold": slo.get("target_threshold"),
                    "timeframe": slo.get("timeframe"),
                    "tags": slo.get("tags", []),
                    "created_at": slo.get("created_at"),
                    "modified_at": slo.get("modified_at"),
                    "monitor_ids": slo.get("monitor_ids", []),
                    "groups": slo.get("groups", []),
                }

                # Get SLO status if available
                overall_status = slo.get("overall_status", [])
                if overall_status:
                    latest = overall_status[0] if isinstance(overall_status, list) else overall_status
                    slo_info["current_sli"] = latest.get("sli_value")
                    slo_info["status"] = latest.get("status")

                    # Track met vs breached
                    if latest.get("status") == "OK":
                        slos_met.append(slo_info)
                    else:
                        slos_breached.append(slo_info)

                slos_data.append(slo_info)

                slo_type = slo.get("type", "unknown")
                by_type[slo_type] = by_type.get(slo_type, 0) + 1

                timeframe = slo.get("timeframe", "unknown")
                by_timeframe[timeframe] = by_timeframe.get(timeframe, 0) + 1

        except Exception as e:
            logger.warning(f"Failed to get SLOs: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="slos",
            raw_data={
                "slos": slos_data,
                "total_slos": len(slos_data),
                "by_type": by_type,
                "by_timeframe": by_timeframe,
                "summary": {
                    "total": len(slos_data),
                    "met": len(slos_met),
                    "breached": len(slos_breached),
                    "unknown": len(slos_data) - len(slos_met) - len(slos_breached),
                },
                "breached_slos": slos_breached,
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.4", "NIST:CA-7"],
            },
        )

    def _evidence_synthetics(self) -> Evidence:
        """Collect synthetic tests for availability monitoring."""
        tests_data: list[dict[str, Any]] = []
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        failing_tests: list[dict[str, Any]] = []

        try:
            response = self._request("GET", "/synthetics/tests")
            data = response.json()
            tests = data.get("tests", [])

            for test in tests:
                test_info = {
                    "public_id": test.get("public_id"),
                    "name": test.get("name"),
                    "type": test.get("type"),
                    "status": test.get("status"),
                    "tags": test.get("tags", []),
                    "locations": test.get("locations", []),
                    "message": test.get("message", ""),
                    "created_at": test.get("created_at"),
                    "modified_at": test.get("modified_at"),
                    "created_by": test.get("created_by", {}),
                    "config": {
                        "request": test.get("config", {}).get("request", {}),
                        "assertions": len(test.get("config", {}).get("assertions", [])),
                    },
                    "options": {
                        "tick_every": test.get("options", {}).get("tick_every"),
                        "min_failure_duration": test.get("options", {}).get("min_failure_duration"),
                        "min_location_failed": test.get("options", {}).get("min_location_failed"),
                    },
                }

                # Get latest result if available
                overall_state = test.get("overall_state")
                if overall_state:
                    test_info["overall_state"] = overall_state
                    if overall_state != 0:  # 0 = OK
                        failing_tests.append(test_info)

                tests_data.append(test_info)

                test_type = test.get("type", "unknown")
                by_type[test_type] = by_type.get(test_type, 0) + 1

                status = test.get("status", "unknown")
                by_status[status] = by_status.get(status, 0) + 1

        except Exception as e:
            logger.warning(f"Failed to get synthetic tests: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="synthetics",
            raw_data={
                "tests": tests_data,
                "total_tests": len(tests_data),
                "by_type": by_type,
                "by_status": by_status,
                "summary": {
                    "total": len(tests_data),
                    "active": sum(1 for t in tests_data if t.get("status") == "live"),
                    "paused": sum(1 for t in tests_data if t.get("status") == "paused"),
                    "failing": len(failing_tests),
                },
                "failing_tests": failing_tests,
            },
            metadata={
                "source": "collector:datadog",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.1", "NIST:CA-7", "ISO27001:A.17.1"],
            },
        )
