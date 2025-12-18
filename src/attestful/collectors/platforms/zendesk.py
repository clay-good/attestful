"""
Zendesk collector for Attestful.

Collects customer support, ticket management, and incident response evidence
from Zendesk Support for compliance frameworks including SOC 2, NIST 800-53,
and ISO 27001.
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
class ZendeskCollectorConfig:
    """Configuration for Zendesk collector."""

    # Authentication - email/token or OAuth
    email: str = ""
    api_token: str = ""

    # Subdomain (e.g., 'company' for company.zendesk.com)
    subdomain: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90


class ZendeskCollector(BaseCollector):
    """
    Zendesk collector for customer support and incident response evidence.

    Collects evidence related to:
    - Support tickets and their lifecycle
    - Ticket SLA and response metrics
    - Agent users and roles
    - Groups and organizations
    - Macros and triggers (automation)
    - Audit logs (Enterprise only)

    Evidence Types:
    - tickets: Support tickets with metadata
    - ticket_metrics: SLA and response time metrics
    - users: Agent and admin users
    - groups: Support groups
    - organizations: Customer organizations
    - macros: Automation macros
    - triggers: Ticket triggers
    - audit_logs: Audit events (Enterprise only)

    Resource Types:
    - zendesk_ticket: Ticket resources
    - zendesk_user: User resources
    - zendesk_group: Group resources
    - zendesk_organization: Organization resources

    Example:
        collector = ZendeskCollector(
            config=ZendeskCollectorConfig(
                email="admin@company.com",
                api_token="your_api_token",
                subdomain="company",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["tickets", "ticket_metrics", "users"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["zendesk_ticket", "zendesk_user"]
        )
    """

    PLATFORM = "zendesk"

    metadata = CollectorMetadata(
        name="ZendeskCollector",
        platform="zendesk",
        description="Collects customer support and incident response evidence from Zendesk",
        mode=CollectorMode.BOTH,
        resource_types=[
            "zendesk_ticket",
            "zendesk_user",
            "zendesk_group",
            "zendesk_organization",
        ],
        evidence_types=[
            "tickets",
            "ticket_metrics",
            "users",
            "groups",
            "organizations",
            "macros",
            "triggers",
            "audit_logs",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "zendesk_ticket",
        "zendesk_user",
        "zendesk_group",
        "zendesk_organization",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "tickets",
        "ticket_metrics",
        "users",
        "groups",
        "organizations",
        "macros",
        "triggers",
        "audit_logs",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "tickets": {
            "soc2": ["CC3.2", "CC7.4", "CC7.5"],
            "nist_800_53": ["IR-4", "IR-5", "IR-6"],
            "iso_27001": ["A.16.1.2", "A.16.1.5"],
            "hitrust": ["11.a", "11.b"],
        },
        "ticket_metrics": {
            "soc2": ["CC3.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["IR-4", "IR-8"],
            "iso_27001": ["A.16.1.6", "A.16.1.7"],
            "hitrust": ["11.c"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.b", "01.c"],
        },
        "groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1"],
            "hitrust": ["01.c"],
        },
        "organizations": {
            "soc2": ["CC3.2", "CC6.1"],
            "nist_800_53": ["AC-2", "PM-5"],
            "iso_27001": ["A.9.2.1", "A.15.1.1"],
            "hitrust": ["01.c", "09.e"],
        },
        "macros": {
            "soc2": ["CC5.2", "CC8.1"],
            "nist_800_53": ["CM-3", "SA-10"],
            "iso_27001": ["A.12.1.2"],
            "hitrust": ["09.b"],
        },
        "triggers": {
            "soc2": ["CC5.2", "CC7.2"],
            "nist_800_53": ["CM-3", "IR-4"],
            "iso_27001": ["A.12.1.2", "A.16.1.1"],
            "hitrust": ["09.b", "11.a"],
        },
        "audit_logs": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    def __init__(self, config: ZendeskCollectorConfig | None = None):
        """Initialize the Zendesk collector."""
        self.config = config or ZendeskCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    @property
    def api_url(self) -> str:
        """Get the Zendesk API base URL."""
        return f"https://{self.config.subdomain}.zendesk.com/api/v2"

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

        # Configure authentication (email/token)
        session.auth = (f"{self.config.email}/token", self.config.api_token)
        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"

        return session

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "results",
    ) -> Iterator[dict[str, Any]]:
        """Paginate through Zendesk API results using cursor-based pagination."""
        params = params or {}
        params["page[size]"] = self.config.page_size
        url = f"{self.api_url}/{endpoint}"

        while url:
            try:
                response = self.session.get(
                    url,
                    params=params if "?" not in url else None,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                data = response.json()

                # Handle different response structures
                items = data.get(results_key, [])
                if not items and isinstance(data, dict):
                    # Try common Zendesk response keys
                    for key in ["tickets", "users", "groups", "organizations", "macros", "triggers", "audit_logs"]:
                        if key in data:
                            items = data[key]
                            break

                for item in items:
                    yield item

                # Get next page URL from links or meta
                links = data.get("links", {})
                meta = data.get("meta", {})

                if links.get("next"):
                    url = links["next"]
                    params = None  # Params are in the URL
                elif meta.get("has_more") and meta.get("after_cursor"):
                    params["page[after]"] = meta["after_cursor"]
                else:
                    break

            except requests.RequestException as e:
                logger.warning(f"Pagination error: {e}")
                break

    def _paginate_offset(
        self,
        endpoint: str,
        results_key: str,
        params: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate using offset-based pagination (for older endpoints)."""
        params = params or {}
        params["per_page"] = self.config.page_size
        page = 1

        while True:
            params["page"] = page
            try:
                response = self.session.get(
                    f"{self.api_url}/{endpoint}",
                    params=params,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                data = response.json()
                items = data.get(results_key, [])

                if not items:
                    break

                for item in items:
                    yield item

                # Check if there are more pages
                if len(items) < self.config.page_size:
                    break

                page += 1

            except requests.RequestException as e:
                logger.warning(f"Pagination error at page {page}: {e}")
                break

    def validate_credentials(self) -> bool:
        """Validate Zendesk credentials."""
        if not self.config.subdomain:
            raise ConfigurationError("Zendesk subdomain is required")
        if not self.config.email:
            raise ConfigurationError("Zendesk email is required")
        if not self.config.api_token:
            raise ConfigurationError("Zendesk api_token is required")

        try:
            response = self.session.get(
                f"{self.api_url}/users/me.json",
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            user_data = response.json().get("user", {})
            logger.info(f"Authenticated as: {user_data.get('name', 'Unknown')}")
            return True
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ConfigurationError("Invalid Zendesk credentials")
            raise ConfigurationError(f"Zendesk API error: {e}")
        except requests.RequestException as e:
            raise ConfigurationError(f"Failed to connect to Zendesk: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Zendesk."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Zendesk evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "tickets": self._collect_tickets_evidence,
            "ticket_metrics": self._collect_ticket_metrics_evidence,
            "users": self._collect_users_evidence,
            "groups": self._collect_groups_evidence,
            "organizations": self._collect_organizations_evidence,
            "macros": self._collect_macros_evidence,
            "triggers": self._collect_triggers_evidence,
            "audit_logs": self._collect_audit_logs_evidence,
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

    def _collect_tickets_evidence(self) -> Evidence:
        """Collect tickets evidence."""
        logger.info("Collecting Zendesk tickets...")
        tickets = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        # Use search endpoint with date filter
        params = {
            "query": f"type:ticket updated>{cutoff_str}",
            "sort_by": "updated_at",
            "sort_order": "desc",
        }

        for ticket in self._paginate("search.json", params=params, results_key="results"):
            if ticket.get("result_type") == "ticket":
                tickets.append(self._normalize_ticket(ticket))

        # Count by status
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for t in tickets:
            status = t.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1
            priority = t.get("priority", "unknown")
            by_priority[priority] = by_priority.get(priority, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="tickets",
            raw_data={
                "tickets": tickets,
                "total_count": len(tickets),
                "by_status": by_status,
                "by_priority": by_priority,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["tickets"],
            },
        )

    def _normalize_ticket(self, ticket: dict[str, Any]) -> dict[str, Any]:
        """Normalize ticket data."""
        return {
            "id": ticket.get("id"),
            "subject": ticket.get("subject"),
            "description": ticket.get("description", "")[:500] if ticket.get("description") else None,
            "status": ticket.get("status"),
            "priority": ticket.get("priority"),
            "type": ticket.get("type"),
            "channel": ticket.get("via", {}).get("channel") if ticket.get("via") else None,
            "requester_id": ticket.get("requester_id"),
            "assignee_id": ticket.get("assignee_id"),
            "group_id": ticket.get("group_id"),
            "organization_id": ticket.get("organization_id"),
            "tags": ticket.get("tags", []),
            "created_at": ticket.get("created_at"),
            "updated_at": ticket.get("updated_at"),
            "solved_at": ticket.get("solved_at") if ticket.get("status") == "solved" else None,
        }

    def _collect_ticket_metrics_evidence(self) -> Evidence:
        """Collect ticket metrics evidence."""
        logger.info("Collecting Zendesk ticket metrics...")
        metrics = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        # Get tickets with metrics
        params = {
            "query": f"type:ticket updated>{cutoff_str}",
        }

        ticket_ids = []
        for ticket in self._paginate("search.json", params=params, results_key="results"):
            if ticket.get("result_type") == "ticket" and ticket.get("id"):
                ticket_ids.append(ticket["id"])

        # Fetch metrics in batches
        for i in range(0, min(len(ticket_ids), 100), 10):  # Limit to 100 tickets
            batch = ticket_ids[i:i+10]
            try:
                response = self.session.get(
                    f"{self.api_url}/tickets/show_many.json",
                    params={"ids": ",".join(str(tid) for tid in batch), "include": "metric_sets"},
                    timeout=self.config.timeout,
                )
                if response.ok:
                    data = response.json()
                    for ticket in data.get("tickets", []):
                        metric_set = ticket.get("metric_set", {})
                        if metric_set:
                            metrics.append({
                                "ticket_id": ticket.get("id"),
                                "reply_time_in_minutes": metric_set.get("reply_time_in_minutes", {}).get("calendar"),
                                "first_resolution_time_in_minutes": metric_set.get("first_resolution_time_in_minutes", {}).get("calendar"),
                                "full_resolution_time_in_minutes": metric_set.get("full_resolution_time_in_minutes", {}).get("calendar"),
                                "agent_wait_time_in_minutes": metric_set.get("agent_wait_time_in_minutes", {}).get("calendar"),
                                "requester_wait_time_in_minutes": metric_set.get("requester_wait_time_in_minutes", {}).get("calendar"),
                                "reopens": metric_set.get("reopens"),
                                "replies": metric_set.get("replies"),
                            })
            except requests.RequestException as e:
                logger.warning(f"Error fetching metrics batch: {e}")

        # Calculate averages
        avg_reply_time = 0
        avg_resolution_time = 0
        if metrics:
            reply_times = [m["reply_time_in_minutes"] for m in metrics if m.get("reply_time_in_minutes")]
            resolution_times = [m["full_resolution_time_in_minutes"] for m in metrics if m.get("full_resolution_time_in_minutes")]
            if reply_times:
                avg_reply_time = sum(reply_times) / len(reply_times)
            if resolution_times:
                avg_resolution_time = sum(resolution_times) / len(resolution_times)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="ticket_metrics",
            raw_data={
                "metrics": metrics,
                "total_count": len(metrics),
                "average_reply_time_minutes": round(avg_reply_time, 2),
                "average_resolution_time_minutes": round(avg_resolution_time, 2),
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["ticket_metrics"],
            },
        )

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Zendesk users...")
        users = []

        for user in self._paginate_offset("users.json", "users"):
            if user.get("role") in ["admin", "agent"]:  # Only staff users
                users.append({
                    "id": user.get("id"),
                    "name": user.get("name"),
                    "email": user.get("email"),
                    "role": user.get("role"),
                    "active": user.get("active"),
                    "suspended": user.get("suspended"),
                    "verified": user.get("verified"),
                    "two_factor_auth_enabled": user.get("two_factor_auth_enabled"),
                    "default_group_id": user.get("default_group_id"),
                    "created_at": user.get("created_at"),
                    "last_login_at": user.get("last_login_at"),
                })

        by_role: dict[str, int] = {}
        for u in users:
            role = u.get("role", "unknown")
            by_role[role] = by_role.get(role, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "active_count": sum(1 for u in users if u.get("active")),
                "by_role": by_role,
                "mfa_enabled_count": sum(1 for u in users if u.get("two_factor_auth_enabled")),
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_groups_evidence(self) -> Evidence:
        """Collect groups evidence."""
        logger.info("Collecting Zendesk groups...")
        groups = []

        for group in self._paginate_offset("groups.json", "groups"):
            groups.append({
                "id": group.get("id"),
                "name": group.get("name"),
                "description": group.get("description"),
                "default": group.get("default"),
                "deleted": group.get("deleted"),
                "created_at": group.get("created_at"),
                "updated_at": group.get("updated_at"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": groups,
                "total_count": len(groups),
                "active_count": sum(1 for g in groups if not g.get("deleted")),
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["groups"],
            },
        )

    def _collect_organizations_evidence(self) -> Evidence:
        """Collect organizations evidence."""
        logger.info("Collecting Zendesk organizations...")
        organizations = []

        for org in self._paginate_offset("organizations.json", "organizations"):
            organizations.append({
                "id": org.get("id"),
                "name": org.get("name"),
                "domain_names": org.get("domain_names", []),
                "shared_tickets": org.get("shared_tickets"),
                "shared_comments": org.get("shared_comments"),
                "group_id": org.get("group_id"),
                "tags": org.get("tags", []),
                "created_at": org.get("created_at"),
                "updated_at": org.get("updated_at"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="organizations",
            raw_data={
                "organizations": organizations,
                "total_count": len(organizations),
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["organizations"],
            },
        )

    def _collect_macros_evidence(self) -> Evidence:
        """Collect macros evidence."""
        logger.info("Collecting Zendesk macros...")
        macros = []

        for macro in self._paginate_offset("macros.json", "macros"):
            macros.append({
                "id": macro.get("id"),
                "title": macro.get("title"),
                "description": macro.get("description"),
                "active": macro.get("active"),
                "restriction": macro.get("restriction"),
                "actions_count": len(macro.get("actions", [])),
                "created_at": macro.get("created_at"),
                "updated_at": macro.get("updated_at"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="macros",
            raw_data={
                "macros": macros,
                "total_count": len(macros),
                "active_count": sum(1 for m in macros if m.get("active")),
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["macros"],
            },
        )

    def _collect_triggers_evidence(self) -> Evidence:
        """Collect triggers evidence."""
        logger.info("Collecting Zendesk triggers...")
        triggers = []

        for trigger in self._paginate_offset("triggers.json", "triggers"):
            triggers.append({
                "id": trigger.get("id"),
                "title": trigger.get("title"),
                "description": trigger.get("description"),
                "active": trigger.get("active"),
                "category_id": trigger.get("category_id"),
                "conditions_count": len(trigger.get("conditions", {}).get("all", [])) + len(trigger.get("conditions", {}).get("any", [])),
                "actions_count": len(trigger.get("actions", [])),
                "created_at": trigger.get("created_at"),
                "updated_at": trigger.get("updated_at"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="triggers",
            raw_data={
                "triggers": triggers,
                "total_count": len(triggers),
                "active_count": sum(1 for t in triggers if t.get("active")),
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["triggers"],
            },
        )

    def _collect_audit_logs_evidence(self) -> Evidence:
        """Collect audit logs evidence (Enterprise only)."""
        logger.info("Collecting Zendesk audit logs...")
        audit_logs = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        try:
            # Audit logs require Enterprise plan
            params = {
                "filter[created_at][]": cutoff_date.isoformat(),
            }

            for log in self._paginate("audit_logs.json", params=params, results_key="audit_logs"):
                audit_logs.append({
                    "id": log.get("id"),
                    "action": log.get("action"),
                    "actor_id": log.get("actor_id"),
                    "actor_name": log.get("actor_name"),
                    "source_type": log.get("source_type"),
                    "source_id": log.get("source_id"),
                    "source_label": log.get("source_label"),
                    "ip_address": log.get("ip_address"),
                    "created_at": log.get("created_at"),
                })

        except requests.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning("Audit logs require Zendesk Enterprise plan")
            else:
                logger.warning(f"Error collecting audit logs: {e}")
        except requests.RequestException as e:
            logger.warning(f"Error collecting audit logs: {e}")

        # Group by action type
        by_action: dict[str, int] = {}
        for log in audit_logs:
            action = log.get("action", "unknown")
            by_action[action] = by_action.get(action, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_logs",
            raw_data={
                "audit_logs": audit_logs,
                "total_count": len(audit_logs),
                "by_action": by_action,
                "days_of_history": self.config.days_of_history,
                "note": "Audit logs require Zendesk Enterprise plan" if not audit_logs else None,
            },
            metadata={
                "source": "collector:zendesk",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_logs"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Zendesk for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Zendesk resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "zendesk_ticket": self._collect_ticket_resources,
            "zendesk_user": self._collect_user_resources,
            "zendesk_group": self._collect_group_resources,
            "zendesk_organization": self._collect_organization_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_ticket_resources(self) -> list[Resource]:
        """Collect ticket resources."""
        logger.info("Collecting Zendesk ticket resources...")
        resources = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        params = {
            "query": f"type:ticket updated>{cutoff_str}",
        }

        count = 0
        max_tickets = 500  # Limit to prevent excessive resource collection

        for ticket in self._paginate("search.json", params=params, results_key="results"):
            if count >= max_tickets:
                logger.info(f"Reached max ticket limit of {max_tickets}")
                break

            if ticket.get("result_type") == "ticket":
                resources.append(
                    Resource(
                        id=str(ticket.get("id", "")),
                        type="zendesk_ticket",
                        provider="zendesk",
                        region="global",
                        name=ticket.get("subject", f"Ticket {ticket.get('id')}"),
                        tags={
                            "status": ticket.get("status", "unknown"),
                            "priority": ticket.get("priority") or "normal",
                            "type": ticket.get("type") or "unknown",
                        },
                        metadata={
                            "subject": ticket.get("subject"),
                            "status": ticket.get("status"),
                            "priority": ticket.get("priority"),
                            "requester_id": ticket.get("requester_id"),
                            "assignee_id": ticket.get("assignee_id"),
                            "group_id": ticket.get("group_id"),
                            "created_at": ticket.get("created_at"),
                            "updated_at": ticket.get("updated_at"),
                        },
                        raw_data=ticket,
                    )
                )
                count += 1

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Zendesk user resources...")
        resources = []

        for user in self._paginate_offset("users.json", "users"):
            if user.get("role") in ["admin", "agent"]:
                resources.append(
                    Resource(
                        id=str(user.get("id", "")),
                        type="zendesk_user",
                        provider="zendesk",
                        region="global",
                        name=user.get("name", "Unknown"),
                        tags={
                            "role": user.get("role", "unknown"),
                            "active": str(user.get("active", False)).lower(),
                            "mfa_enabled": str(user.get("two_factor_auth_enabled", False)).lower(),
                        },
                        metadata={
                            "name": user.get("name"),
                            "email": user.get("email"),
                            "role": user.get("role"),
                            "active": user.get("active"),
                            "suspended": user.get("suspended"),
                            "verified": user.get("verified"),
                            "two_factor_auth_enabled": user.get("two_factor_auth_enabled"),
                            "last_login_at": user.get("last_login_at"),
                        },
                        raw_data=user,
                    )
                )

        return resources

    def _collect_group_resources(self) -> list[Resource]:
        """Collect group resources."""
        logger.info("Collecting Zendesk group resources...")
        resources = []

        for group in self._paginate_offset("groups.json", "groups"):
            resources.append(
                Resource(
                    id=str(group.get("id", "")),
                    type="zendesk_group",
                    provider="zendesk",
                    region="global",
                    name=group.get("name", "Unknown"),
                    tags={
                        "default": str(group.get("default", False)).lower(),
                        "deleted": str(group.get("deleted", False)).lower(),
                    },
                    metadata={
                        "name": group.get("name"),
                        "description": group.get("description"),
                        "default": group.get("default"),
                        "deleted": group.get("deleted"),
                    },
                    raw_data=group,
                )
            )

        return resources

    def _collect_organization_resources(self) -> list[Resource]:
        """Collect organization resources."""
        logger.info("Collecting Zendesk organization resources...")
        resources = []

        for org in self._paginate_offset("organizations.json", "organizations"):
            resources.append(
                Resource(
                    id=str(org.get("id", "")),
                    type="zendesk_organization",
                    provider="zendesk",
                    region="global",
                    name=org.get("name", "Unknown"),
                    tags={
                        "shared_tickets": str(org.get("shared_tickets", False)).lower(),
                    },
                    metadata={
                        "name": org.get("name"),
                        "domain_names": org.get("domain_names", []),
                        "shared_tickets": org.get("shared_tickets"),
                        "shared_comments": org.get("shared_comments"),
                        "group_id": org.get("group_id"),
                    },
                    raw_data=org,
                )
            )

        return resources
