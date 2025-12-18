"""
PagerDuty collector for Attestful.

Collects incident management, on-call scheduling, and response evidence
from PagerDuty for compliance frameworks including SOC 2, NIST 800-53,
ISO 27001, and HITRUST.
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
class PagerDutyCollectorConfig:
    """Configuration for PagerDuty collector."""

    # API Token (REST API v2)
    api_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100  # PagerDuty max is 100

    # Collection options
    days_of_history: int = 90


class PagerDutyCollector(BaseCollector):
    """
    PagerDuty collector for incident management evidence.

    Collects evidence related to:
    - Incidents and their resolution
    - On-call schedules and coverage
    - Escalation policies
    - Services and integrations
    - Users and teams
    - Response analytics

    Evidence Types:
    - incidents: Incident records and resolution data
    - services: Service definitions and configurations
    - schedules: On-call schedules and coverage
    - escalation_policies: Escalation policy configurations
    - users: User accounts and contact methods
    - teams: Team configurations
    - analytics: Incident response analytics

    Resource Types:
    - pagerduty_incident: Incident resources
    - pagerduty_service: Service resources
    - pagerduty_schedule: Schedule resources
    - pagerduty_user: User resources

    Example:
        collector = PagerDutyCollector(
            config=PagerDutyCollectorConfig(
                api_token="your-api-token",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["incidents", "services", "schedules"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["pagerduty_incident", "pagerduty_service"]
        )
    """

    PLATFORM = "pagerduty"

    metadata = CollectorMetadata(
        name="PagerDutyCollector",
        platform="pagerduty",
        description="Collects incident management and on-call evidence from PagerDuty",
        mode=CollectorMode.BOTH,
        resource_types=[
            "pagerduty_incident",
            "pagerduty_service",
            "pagerduty_schedule",
            "pagerduty_user",
        ],
        evidence_types=[
            "incidents",
            "services",
            "schedules",
            "escalation_policies",
            "users",
            "teams",
            "analytics",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "pagerduty_incident",
        "pagerduty_service",
        "pagerduty_schedule",
        "pagerduty_user",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "incidents",
        "services",
        "schedules",
        "escalation_policies",
        "users",
        "teams",
        "analytics",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "incidents": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4", "CC7.5"],
            "nist_800_53": ["IR-4", "IR-5", "IR-6", "IR-8"],
            "iso_27001": ["A.16.1.1", "A.16.1.2", "A.16.1.4", "A.16.1.5"],
            "hitrust": ["11.a", "11.b", "11.c"],
        },
        "services": {
            "soc2": ["CC7.1", "CC7.2", "CC8.1"],
            "nist_800_53": ["CM-2", "CM-6", "SA-3"],
            "iso_27001": ["A.12.1.1", "A.12.1.2"],
            "hitrust": ["09.a", "09.b"],
        },
        "schedules": {
            "soc2": ["CC7.2", "CC7.4"],
            "nist_800_53": ["IR-7", "CP-2", "CP-10"],
            "iso_27001": ["A.16.1.1", "A.17.1.2"],
            "hitrust": ["11.a", "12.a"],
        },
        "escalation_policies": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["IR-4", "IR-7", "CP-2"],
            "iso_27001": ["A.16.1.1", "A.16.1.2"],
            "hitrust": ["11.a", "11.b"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.b", "01.c"],
        },
        "teams": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1"],
            "hitrust": ["01.c"],
        },
        "analytics": {
            "soc2": ["CC7.2", "CC7.4", "CC7.5"],
            "nist_800_53": ["IR-4", "IR-5", "IR-8"],
            "iso_27001": ["A.16.1.6"],
            "hitrust": ["11.c", "11.d"],
        },
    }

    def __init__(self, config: PagerDutyCollectorConfig | None = None):
        """Initialize the PagerDuty collector."""
        self.config = config or PagerDutyCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    @property
    def api_url(self) -> str:
        """Get the PagerDuty API base URL."""
        return "https://api.pagerduty.com"

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
        session.headers["Content-Type"] = "application/json"
        session.headers["Authorization"] = f"Token token={self.config.api_token}"

        return session

    def _make_request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated API request."""
        url = f"{self.api_url}/{endpoint}"
        params = params or {}

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"API request failed: {endpoint} - {e}")
            raise

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "data",
    ) -> Iterator[dict[str, Any]]:
        """Paginate through PagerDuty API results using offset-based pagination."""
        params = params or {}
        params["limit"] = self.config.page_size
        offset = 0

        while True:
            params["offset"] = offset

            try:
                data = self._make_request(endpoint, params=params)

                items = data.get(results_key, [])
                for item in items:
                    yield item

                # Check if there are more results
                if not data.get("more", False):
                    break

                offset += len(items)

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate PagerDuty credentials."""
        if not self.config.api_token:
            raise ConfigurationError("PagerDuty api_token is required")

        try:
            # Test authentication by getting abilities
            data = self._make_request("abilities")
            abilities = data.get("abilities", [])
            logger.info(f"Authenticated to PagerDuty with {len(abilities)} abilities")
            return True
        except requests.RequestException as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                raise ConfigurationError("Invalid PagerDuty API token")
            raise ConfigurationError(f"Failed to validate PagerDuty credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from PagerDuty."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting PagerDuty evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "incidents": self._collect_incidents_evidence,
            "services": self._collect_services_evidence,
            "schedules": self._collect_schedules_evidence,
            "escalation_policies": self._collect_escalation_policies_evidence,
            "users": self._collect_users_evidence,
            "teams": self._collect_teams_evidence,
            "analytics": self._collect_analytics_evidence,
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

    def _collect_incidents_evidence(self) -> Evidence:
        """Collect incidents evidence."""
        logger.info("Collecting PagerDuty incidents...")
        incidents = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        params = {
            "since": since_str,
            "statuses[]": ["triggered", "acknowledged", "resolved"],
        }

        for incident in self._paginate("incidents", params=params, results_key="incidents"):
            incidents.append({
                "id": incident.get("id"),
                "incident_number": incident.get("incident_number"),
                "title": incident.get("title"),
                "status": incident.get("status"),
                "urgency": incident.get("urgency"),
                "priority": incident.get("priority", {}).get("name") if incident.get("priority") else None,
                "service": {
                    "id": incident.get("service", {}).get("id"),
                    "name": incident.get("service", {}).get("summary"),
                },
                "escalation_policy": {
                    "id": incident.get("escalation_policy", {}).get("id"),
                    "name": incident.get("escalation_policy", {}).get("summary"),
                },
                "created_at": incident.get("created_at"),
                "last_status_change_at": incident.get("last_status_change_at"),
                "resolved_at": incident.get("resolved_at") if incident.get("status") == "resolved" else None,
                "assignments": [
                    {"user_id": a.get("assignee", {}).get("id"), "user_name": a.get("assignee", {}).get("summary")}
                    for a in incident.get("assignments", [])
                ],
                "acknowledgements": [
                    {"user_id": a.get("acknowledger", {}).get("id"), "at": a.get("at")}
                    for a in incident.get("acknowledgements", [])
                ],
            })

        # Calculate metrics
        resolved_count = sum(1 for i in incidents if i.get("status") == "resolved")
        high_urgency_count = sum(1 for i in incidents if i.get("urgency") == "high")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="incidents",
            raw_data={
                "incidents": incidents,
                "total_count": len(incidents),
                "resolved_count": resolved_count,
                "high_urgency_count": high_urgency_count,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["incidents"],
            },
        )

    def _collect_services_evidence(self) -> Evidence:
        """Collect services evidence."""
        logger.info("Collecting PagerDuty services...")
        services = []

        for service in self._paginate("services", results_key="services"):
            integrations = []
            # Get integrations for the service
            try:
                integ_data = self._make_request(f"services/{service.get('id')}/integrations")
                integrations = [
                    {"id": i.get("id"), "type": i.get("type"), "name": i.get("name")}
                    for i in integ_data.get("integrations", [])
                ]
            except requests.RequestException:
                pass

            services.append({
                "id": service.get("id"),
                "name": service.get("name"),
                "description": service.get("description"),
                "status": service.get("status"),
                "escalation_policy": {
                    "id": service.get("escalation_policy", {}).get("id"),
                    "name": service.get("escalation_policy", {}).get("summary"),
                },
                "auto_resolve_timeout": service.get("auto_resolve_timeout"),
                "acknowledgement_timeout": service.get("acknowledgement_timeout"),
                "alert_creation": service.get("alert_creation"),
                "alert_grouping": service.get("alert_grouping"),
                "alert_grouping_timeout": service.get("alert_grouping_timeout"),
                "integrations": integrations,
                "teams": [
                    {"id": t.get("id"), "name": t.get("summary")}
                    for t in service.get("teams", [])
                ],
                "created_at": service.get("created_at"),
            })

        # Categorize by status
        active_count = sum(1 for s in services if s.get("status") == "active")
        disabled_count = sum(1 for s in services if s.get("status") == "disabled")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="services",
            raw_data={
                "services": services,
                "total_count": len(services),
                "active_count": active_count,
                "disabled_count": disabled_count,
            },
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["services"],
            },
        )

    def _collect_schedules_evidence(self) -> Evidence:
        """Collect schedules evidence."""
        logger.info("Collecting PagerDuty schedules...")
        schedules = []

        for schedule in self._paginate("schedules", results_key="schedules"):
            # Get schedule details including on-call users
            try:
                schedule_data = self._make_request(f"schedules/{schedule.get('id')}")
                schedule_detail = schedule_data.get("schedule", {})
            except requests.RequestException:
                schedule_detail = schedule

            schedules.append({
                "id": schedule_detail.get("id"),
                "name": schedule_detail.get("name"),
                "description": schedule_detail.get("description"),
                "time_zone": schedule_detail.get("time_zone"),
                "users": [
                    {"id": u.get("id"), "name": u.get("summary")}
                    for u in schedule_detail.get("users", [])
                ],
                "escalation_policies": [
                    {"id": ep.get("id"), "name": ep.get("summary")}
                    for ep in schedule_detail.get("escalation_policies", [])
                ],
                "teams": [
                    {"id": t.get("id"), "name": t.get("summary")}
                    for t in schedule_detail.get("teams", [])
                ],
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="schedules",
            raw_data={
                "schedules": schedules,
                "total_count": len(schedules),
            },
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["schedules"],
            },
        )

    def _collect_escalation_policies_evidence(self) -> Evidence:
        """Collect escalation policies evidence."""
        logger.info("Collecting PagerDuty escalation policies...")
        policies = []

        for policy in self._paginate("escalation_policies", results_key="escalation_policies"):
            rules = []
            for rule in policy.get("escalation_rules", []):
                targets = []
                for target in rule.get("targets", []):
                    targets.append({
                        "id": target.get("id"),
                        "type": target.get("type"),
                        "name": target.get("summary"),
                    })
                rules.append({
                    "escalation_delay_in_minutes": rule.get("escalation_delay_in_minutes"),
                    "targets": targets,
                })

            policies.append({
                "id": policy.get("id"),
                "name": policy.get("name"),
                "description": policy.get("description"),
                "num_loops": policy.get("num_loops"),
                "on_call_handoff_notifications": policy.get("on_call_handoff_notifications"),
                "escalation_rules": rules,
                "services": [
                    {"id": s.get("id"), "name": s.get("summary")}
                    for s in policy.get("services", [])
                ],
                "teams": [
                    {"id": t.get("id"), "name": t.get("summary")}
                    for t in policy.get("teams", [])
                ],
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="escalation_policies",
            raw_data={
                "escalation_policies": policies,
                "total_count": len(policies),
            },
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["escalation_policies"],
            },
        )

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting PagerDuty users...")
        users = []

        for user in self._paginate("users", results_key="users"):
            # Get user contact methods
            contact_methods = []
            try:
                contact_data = self._make_request(f"users/{user.get('id')}/contact_methods")
                contact_methods = [
                    {"type": c.get("type"), "address": c.get("address")}
                    for c in contact_data.get("contact_methods", [])
                ]
            except requests.RequestException:
                pass

            users.append({
                "id": user.get("id"),
                "name": user.get("name"),
                "email": user.get("email"),
                "role": user.get("role"),
                "job_title": user.get("job_title"),
                "time_zone": user.get("time_zone"),
                "invitation_sent": user.get("invitation_sent"),
                "contact_methods": contact_methods,
                "teams": [
                    {"id": t.get("id"), "name": t.get("summary")}
                    for t in user.get("teams", [])
                ],
            })

        # Categorize by role
        role_counts = {}
        for user in users:
            role = user.get("role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "role_counts": role_counts,
            },
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_teams_evidence(self) -> Evidence:
        """Collect teams evidence."""
        logger.info("Collecting PagerDuty teams...")
        teams = []

        for team in self._paginate("teams", results_key="teams"):
            # Get team members
            members = []
            try:
                members_data = self._make_request(f"teams/{team.get('id')}/members")
                members = [
                    {"id": m.get("user", {}).get("id"), "name": m.get("user", {}).get("summary"), "role": m.get("role")}
                    for m in members_data.get("members", [])
                ]
            except requests.RequestException:
                pass

            teams.append({
                "id": team.get("id"),
                "name": team.get("name"),
                "description": team.get("description"),
                "member_count": len(members),
                "members": members,
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="teams",
            raw_data={
                "teams": teams,
                "total_count": len(teams),
            },
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["teams"],
            },
        )

    def _collect_analytics_evidence(self) -> Evidence:
        """Collect analytics evidence."""
        logger.info("Collecting PagerDuty analytics...")

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        until = datetime.now(timezone.utc)

        analytics = {
            "period": {
                "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            "summary": {},
        }

        # Try to get incident analytics (requires analytics feature)
        try:
            # Get raw incident data for analytics
            params = {
                "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "until": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }

            incidents = list(self._paginate("incidents", params=params, results_key="incidents"))

            # Calculate metrics manually
            total_incidents = len(incidents)
            resolved_incidents = [i for i in incidents if i.get("status") == "resolved"]

            # Calculate MTTA (Mean Time to Acknowledge)
            acknowledge_times = []
            for incident in incidents:
                if incident.get("acknowledgements"):
                    created = datetime.fromisoformat(incident["created_at"].replace("Z", "+00:00"))
                    first_ack = min(
                        datetime.fromisoformat(a["at"].replace("Z", "+00:00"))
                        for a in incident["acknowledgements"]
                    )
                    acknowledge_times.append((first_ack - created).total_seconds())

            # Calculate MTTR (Mean Time to Resolve)
            resolve_times = []
            for incident in resolved_incidents:
                if incident.get("resolved_at"):
                    created = datetime.fromisoformat(incident["created_at"].replace("Z", "+00:00"))
                    resolved = datetime.fromisoformat(incident["resolved_at"].replace("Z", "+00:00"))
                    resolve_times.append((resolved - created).total_seconds())

            analytics["summary"] = {
                "total_incidents": total_incidents,
                "resolved_incidents": len(resolved_incidents),
                "mean_time_to_acknowledge_seconds": sum(acknowledge_times) / len(acknowledge_times) if acknowledge_times else None,
                "mean_time_to_resolve_seconds": sum(resolve_times) / len(resolve_times) if resolve_times else None,
                "incidents_by_urgency": {
                    "high": sum(1 for i in incidents if i.get("urgency") == "high"),
                    "low": sum(1 for i in incidents if i.get("urgency") == "low"),
                },
            }
        except Exception as e:
            logger.warning(f"Error collecting analytics: {e}")
            analytics["summary"] = {"error": str(e)}

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="analytics",
            raw_data=analytics,
            metadata={
                "source": "collector:pagerduty",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["analytics"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from PagerDuty for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting PagerDuty resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "pagerduty_incident": self._collect_incident_resources,
            "pagerduty_service": self._collect_service_resources,
            "pagerduty_schedule": self._collect_schedule_resources,
            "pagerduty_user": self._collect_user_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_incident_resources(self) -> list[Resource]:
        """Collect incident resources."""
        logger.info("Collecting PagerDuty incident resources...")
        resources = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        params = {
            "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        for incident in self._paginate("incidents", params=params, results_key="incidents"):
            resources.append(
                Resource(
                    id=str(incident.get("id", "")),
                    type="pagerduty_incident",
                    provider="pagerduty",
                    region="global",
                    name=incident.get("title", "Unknown"),
                    tags={
                        "status": incident.get("status", "unknown"),
                        "urgency": incident.get("urgency", "unknown"),
                        "service_id": incident.get("service", {}).get("id", ""),
                    },
                    metadata={
                        "id": incident.get("id"),
                        "incident_number": incident.get("incident_number"),
                        "title": incident.get("title"),
                        "status": incident.get("status"),
                        "urgency": incident.get("urgency"),
                        "service_id": incident.get("service", {}).get("id"),
                        "service_name": incident.get("service", {}).get("summary"),
                        "created_at": incident.get("created_at"),
                        "resolved_at": incident.get("resolved_at"),
                    },
                    raw_data=incident,
                )
            )

        return resources

    def _collect_service_resources(self) -> list[Resource]:
        """Collect service resources."""
        logger.info("Collecting PagerDuty service resources...")
        resources = []

        for service in self._paginate("services", results_key="services"):
            resources.append(
                Resource(
                    id=str(service.get("id", "")),
                    type="pagerduty_service",
                    provider="pagerduty",
                    region="global",
                    name=service.get("name", "Unknown"),
                    tags={
                        "status": service.get("status", "unknown"),
                        "alert_creation": service.get("alert_creation", "unknown"),
                    },
                    metadata={
                        "id": service.get("id"),
                        "name": service.get("name"),
                        "description": service.get("description"),
                        "status": service.get("status"),
                        "auto_resolve_timeout": service.get("auto_resolve_timeout"),
                        "acknowledgement_timeout": service.get("acknowledgement_timeout"),
                        "alert_creation": service.get("alert_creation"),
                        "escalation_policy_id": service.get("escalation_policy", {}).get("id"),
                    },
                    raw_data=service,
                )
            )

        return resources

    def _collect_schedule_resources(self) -> list[Resource]:
        """Collect schedule resources."""
        logger.info("Collecting PagerDuty schedule resources...")
        resources = []

        for schedule in self._paginate("schedules", results_key="schedules"):
            user_count = len(schedule.get("users", []))
            resources.append(
                Resource(
                    id=str(schedule.get("id", "")),
                    type="pagerduty_schedule",
                    provider="pagerduty",
                    region="global",
                    name=schedule.get("name", "Unknown"),
                    tags={
                        "time_zone": schedule.get("time_zone", "UTC"),
                        "user_count": str(user_count),
                    },
                    metadata={
                        "id": schedule.get("id"),
                        "name": schedule.get("name"),
                        "description": schedule.get("description"),
                        "time_zone": schedule.get("time_zone"),
                        "user_count": user_count,
                    },
                    raw_data=schedule,
                )
            )

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting PagerDuty user resources...")
        resources = []

        for user in self._paginate("users", results_key="users"):
            resources.append(
                Resource(
                    id=str(user.get("id", "")),
                    type="pagerduty_user",
                    provider="pagerduty",
                    region="global",
                    name=user.get("name", "Unknown"),
                    tags={
                        "role": user.get("role", "unknown"),
                        "invitation_sent": str(user.get("invitation_sent", False)).lower(),
                    },
                    metadata={
                        "id": user.get("id"),
                        "name": user.get("name"),
                        "email": user.get("email"),
                        "role": user.get("role"),
                        "job_title": user.get("job_title"),
                        "time_zone": user.get("time_zone"),
                        "invitation_sent": user.get("invitation_sent"),
                    },
                    raw_data=user,
                )
            )

        return resources
