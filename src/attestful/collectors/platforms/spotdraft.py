"""
SpotDraft collector for contract management evidence.

Collects contract lifecycle data including contracts, templates, approvals,
and audit trails for compliance evidence.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.models import CollectionResult, Evidence, Resource

logger = logging.getLogger(__name__)


@dataclass
class SpotDraftCollectorConfig:
    """Configuration for SpotDraft collector."""

    api_key: str = ""
    base_url: str = "https://api.spotdraft.com"
    timeout: int = 30
    page_size: int = 50
    days_of_history: int = 90


class SpotDraftCollector(BaseCollector):
    """
    Collector for SpotDraft contract management platform.

    Collects:
    - Contracts: Active, pending, and executed contracts
    - Templates: Contract templates and their versions
    - Approvals: Approval workflows and history
    - Users: Team members and their roles
    - Audit logs: Contract activity and changes

    Evidence types map to compliance controls for:
    - SOC 2: CC1.4 (Board Oversight), CC3.1 (Risk Assessment), CC5.2 (Control Activities)
    - NIST 800-53: SA-4 (Acquisition Process), SA-22 (Unsupported System Components)
    - ISO 27001: A.13.2.4 (Confidentiality Agreements), A.15.1.2 (Security in Supplier Agreements)
    - HITRUST: 05.i (Identification of Risks), 09.e (Service Delivery)
    """

    PLATFORM = "spotdraft"
    SUPPORTED_RESOURCE_TYPES = [
        "spotdraft_contract",
        "spotdraft_template",
        "spotdraft_user",
        "spotdraft_folder",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "contracts",
        "templates",
        "approvals",
        "users",
        "audit_logs",
        "folders",
    ]

    # Map evidence types to compliance framework controls
    EVIDENCE_CONTROL_MAPPINGS = {
        "contracts": {
            "soc2": ["CC1.4", "CC3.1", "CC5.2", "CC9.2"],
            "nist_800_53": ["SA-4", "SA-22", "PS-7", "SR-3"],
            "iso_27001": ["A.13.2.4", "A.15.1.2", "A.15.2.1"],
            "hitrust": ["05.i", "09.e", "09.f"],
        },
        "templates": {
            "soc2": ["CC5.2", "CC5.3"],
            "nist_800_53": ["SA-4", "SA-5"],
            "iso_27001": ["A.13.2.4", "A.15.1.1"],
            "hitrust": ["05.a", "09.e"],
        },
        "approvals": {
            "soc2": ["CC5.2", "CC5.3", "CC6.1"],
            "nist_800_53": ["CA-7", "PM-14", "SA-4"],
            "iso_27001": ["A.12.1.2", "A.15.1.2"],
            "hitrust": ["01.a", "05.i"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-5", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.q"],
        },
        "audit_logs": {
            "soc2": ["CC4.1", "CC4.2", "CC7.2"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.2", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab", "09.ad"],
        },
        "folders": {
            "soc2": ["CC5.2", "CC6.1"],
            "nist_800_53": ["AC-3", "MP-2"],
            "iso_27001": ["A.8.2.1", "A.8.2.2"],
            "hitrust": ["06.c", "09.o"],
        },
    }

    def __init__(self, config: SpotDraftCollectorConfig | None = None):
        """Initialize SpotDraft collector."""
        self.config = config or SpotDraftCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def metadata(self) -> CollectorMetadata:
        """Return collector metadata."""
        return CollectorMetadata(
            name="SpotDraft Collector",
            platform=self.PLATFORM,
            description="Collects contract management evidence from SpotDraft",
            mode=CollectorMode.BOTH,
            resource_types=self.SUPPORTED_RESOURCE_TYPES,
            evidence_types=self.SUPPORTED_EVIDENCE_TYPES,
            version="1.0.0",
        )

    @property
    def session(self) -> requests.Session:
        """Get or create HTTP session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
        return self._session

    @property
    def api_url(self) -> str:
        """Return the API base URL."""
        return self.config.base_url.rstrip("/")

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> dict:
        """Make an API request to SpotDraft."""
        url = f"{self.api_url}{endpoint}"

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"SpotDraft API request failed: {e}")
            raise

    def _paginate(
        self,
        endpoint: str,
        params: dict | None = None,
        data_key: str = "data",
    ) -> list[dict]:
        """Paginate through API results."""
        results = []
        params = params or {}
        params["limit"] = self.config.page_size
        offset = 0

        while True:
            params["offset"] = offset
            try:
                response = self._make_request("GET", endpoint, params=params)
                data = response.get(data_key, [])

                if not data:
                    break

                results.extend(data)

                # Check for more pages
                total = response.get("total", 0)
                if len(results) >= total or len(data) < self.config.page_size:
                    break

                offset += self.config.page_size

            except requests.RequestException:
                if not results:
                    raise
                break

        return results

    def validate_credentials(self) -> bool:
        """Validate SpotDraft credentials."""
        if not self.config.api_key:
            raise ConfigurationError("SpotDraft api_key is required")

        try:
            # Test authentication by getting current user
            response = self._make_request("GET", "/v1/me")
            user_name = response.get("name", "Unknown")
            logger.info(f"Authenticated to SpotDraft as: {user_name}")
            return True
        except requests.RequestException as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                raise ConfigurationError("Invalid SpotDraft API key")
            raise ConfigurationError(f"Failed to validate SpotDraft credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from SpotDraft."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting SpotDraft evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "contracts": self._collect_contracts_evidence,
            "templates": self._collect_templates_evidence,
            "approvals": self._collect_approvals_evidence,
            "users": self._collect_users_evidence,
            "audit_logs": self._collect_audit_logs_evidence,
            "folders": self._collect_folders_evidence,
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

    def _collect_contracts_evidence(self) -> Evidence:
        """Collect contracts evidence."""
        logger.info("Collecting SpotDraft contracts...")

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        since_str = since.strftime("%Y-%m-%d")

        contracts = self._paginate(
            "/v1/contracts",
            params={"updated_after": since_str},
        )

        # Categorize contracts by status
        status_counts = {}
        type_counts = {}
        total_value = 0.0

        for contract in contracts:
            status = contract.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            contract_type = contract.get("type", "unknown")
            type_counts[contract_type] = type_counts.get(contract_type, 0) + 1

            # Sum contract values if available
            value = contract.get("value", 0) or 0
            total_value += float(value)

        # Identify contracts expiring soon (within 30 days)
        expiring_soon = []
        thirty_days = datetime.now(timezone.utc) + timedelta(days=30)

        for contract in contracts:
            expiry_date_str = contract.get("expiry_date")
            if expiry_date_str:
                try:
                    expiry = datetime.fromisoformat(expiry_date_str.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) < expiry <= thirty_days:
                        expiring_soon.append({
                            "id": contract.get("id"),
                            "name": contract.get("name"),
                            "expiry_date": expiry_date_str,
                            "counterparty": contract.get("counterparty", {}).get("name"),
                        })
                except (ValueError, TypeError):
                    pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="contracts",
            raw_data={
                "contracts": [
                    {
                        "id": c.get("id"),
                        "name": c.get("name"),
                        "status": c.get("status"),
                        "type": c.get("type"),
                        "created_at": c.get("created_at"),
                        "updated_at": c.get("updated_at"),
                        "expiry_date": c.get("expiry_date"),
                        "effective_date": c.get("effective_date"),
                        "value": c.get("value"),
                        "currency": c.get("currency"),
                        "counterparty": c.get("counterparty", {}).get("name"),
                        "owner": c.get("owner", {}).get("email"),
                        "tags": c.get("tags", []),
                    }
                    for c in contracts
                ],
                "total_count": len(contracts),
                "status_counts": status_counts,
                "type_counts": type_counts,
                "total_value": total_value,
                "expiring_soon": expiring_soon,
                "expiring_soon_count": len(expiring_soon),
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:spotdraft",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["contracts"],
            },
        )

    def _collect_templates_evidence(self) -> Evidence:
        """Collect contract templates evidence."""
        logger.info("Collecting SpotDraft templates...")

        templates = self._paginate("/v1/templates")

        # Categorize templates
        status_counts = {}
        category_counts = {}

        for template in templates:
            status = template.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            category = template.get("category", "uncategorized")
            category_counts[category] = category_counts.get(category, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="templates",
            raw_data={
                "templates": [
                    {
                        "id": t.get("id"),
                        "name": t.get("name"),
                        "status": t.get("status"),
                        "category": t.get("category"),
                        "version": t.get("version"),
                        "created_at": t.get("created_at"),
                        "updated_at": t.get("updated_at"),
                        "created_by": t.get("created_by", {}).get("email"),
                        "usage_count": t.get("usage_count", 0),
                    }
                    for t in templates
                ],
                "total_count": len(templates),
                "status_counts": status_counts,
                "category_counts": category_counts,
            },
            metadata={
                "source": "collector:spotdraft",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["templates"],
            },
        )

    def _collect_approvals_evidence(self) -> Evidence:
        """Collect approval workflow evidence."""
        logger.info("Collecting SpotDraft approvals...")

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        since_str = since.strftime("%Y-%m-%d")

        approvals = self._paginate(
            "/v1/approvals",
            params={"updated_after": since_str},
        )

        # Analyze approvals
        status_counts = {}
        avg_approval_time_hours = 0.0
        total_approval_time = 0.0
        completed_count = 0

        for approval in approvals:
            status = approval.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            # Calculate approval time for completed approvals
            if status in ("approved", "rejected"):
                created = approval.get("created_at")
                completed = approval.get("completed_at")
                if created and completed:
                    try:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        completed_dt = datetime.fromisoformat(completed.replace("Z", "+00:00"))
                        hours = (completed_dt - created_dt).total_seconds() / 3600
                        total_approval_time += hours
                        completed_count += 1
                    except (ValueError, TypeError):
                        pass

        if completed_count > 0:
            avg_approval_time_hours = round(total_approval_time / completed_count, 2)

        # Find pending approvals
        pending_approvals = [
            {
                "id": a.get("id"),
                "contract_id": a.get("contract_id"),
                "contract_name": a.get("contract_name"),
                "approver": a.get("approver", {}).get("email"),
                "created_at": a.get("created_at"),
                "stage": a.get("stage"),
            }
            for a in approvals
            if a.get("status") == "pending"
        ]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="approvals",
            raw_data={
                "approvals": [
                    {
                        "id": a.get("id"),
                        "contract_id": a.get("contract_id"),
                        "contract_name": a.get("contract_name"),
                        "status": a.get("status"),
                        "stage": a.get("stage"),
                        "approver": a.get("approver", {}).get("email"),
                        "created_at": a.get("created_at"),
                        "completed_at": a.get("completed_at"),
                        "comment": a.get("comment"),
                    }
                    for a in approvals
                ],
                "total_count": len(approvals),
                "status_counts": status_counts,
                "pending_count": len(pending_approvals),
                "pending_approvals": pending_approvals,
                "avg_approval_time_hours": avg_approval_time_hours,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:spotdraft",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["approvals"],
            },
        )

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting SpotDraft users...")

        users = self._paginate("/v1/users")

        # Categorize users
        role_counts = {}
        active_count = 0
        inactive_count = 0

        for user in users:
            role = user.get("role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1

            if user.get("status") == "active":
                active_count += 1
            else:
                inactive_count += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": [
                    {
                        "id": u.get("id"),
                        "email": u.get("email"),
                        "name": u.get("name"),
                        "role": u.get("role"),
                        "status": u.get("status"),
                        "created_at": u.get("created_at"),
                        "last_login_at": u.get("last_login_at"),
                        "mfa_enabled": u.get("mfa_enabled", False),
                        "teams": [t.get("name") for t in u.get("teams", [])],
                    }
                    for u in users
                ],
                "total_count": len(users),
                "role_counts": role_counts,
                "active_count": active_count,
                "inactive_count": inactive_count,
            },
            metadata={
                "source": "collector:spotdraft",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_audit_logs_evidence(self) -> Evidence:
        """Collect audit logs evidence."""
        logger.info("Collecting SpotDraft audit logs...")

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        since_str = since.strftime("%Y-%m-%d")

        audit_logs = self._paginate(
            "/v1/audit-logs",
            params={"from_date": since_str},
            data_key="logs",
        )

        # Categorize by action type
        action_counts = {}
        resource_counts = {}

        for log in audit_logs:
            action = log.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

            resource = log.get("resource_type", "unknown")
            resource_counts[resource] = resource_counts.get(resource, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_logs",
            raw_data={
                "audit_logs": [
                    {
                        "id": l.get("id"),
                        "action": l.get("action"),
                        "resource_type": l.get("resource_type"),
                        "resource_id": l.get("resource_id"),
                        "resource_name": l.get("resource_name"),
                        "actor": l.get("actor", {}).get("email"),
                        "timestamp": l.get("timestamp"),
                        "ip_address": l.get("ip_address"),
                        "details": l.get("details"),
                    }
                    for l in audit_logs
                ],
                "total_count": len(audit_logs),
                "action_counts": action_counts,
                "resource_counts": resource_counts,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:spotdraft",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_logs"],
            },
        )

    def _collect_folders_evidence(self) -> Evidence:
        """Collect folders/organization evidence."""
        logger.info("Collecting SpotDraft folders...")

        folders = self._paginate("/v1/folders")

        # Build folder hierarchy info
        root_folders = [f for f in folders if not f.get("parent_id")]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="folders",
            raw_data={
                "folders": [
                    {
                        "id": f.get("id"),
                        "name": f.get("name"),
                        "parent_id": f.get("parent_id"),
                        "created_at": f.get("created_at"),
                        "contract_count": f.get("contract_count", 0),
                        "permissions": f.get("permissions", []),
                    }
                    for f in folders
                ],
                "total_count": len(folders),
                "root_folder_count": len(root_folders),
            },
            metadata={
                "source": "collector:spotdraft",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["folders"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from SpotDraft."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting SpotDraft resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "spotdraft_contract": self._collect_contract_resources,
            "spotdraft_template": self._collect_template_resources,
            "spotdraft_user": self._collect_user_resources,
            "spotdraft_folder": self._collect_folder_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type}: {e}")

        return resources

    def _collect_contract_resources(self) -> list[Resource]:
        """Collect contract resources."""
        logger.info("Collecting SpotDraft contract resources...")
        resources = []

        contracts = self._paginate("/v1/contracts")

        for contract in contracts:
            counterparty = contract.get("counterparty", {}) or {}
            owner = contract.get("owner", {}) or {}

            resources.append(
                Resource(
                    id=contract.get("id", ""),
                    type="spotdraft_contract",
                    provider="spotdraft",
                    region="global",
                    name=contract.get("name", ""),
                    tags=contract.get("tags", []),
                    metadata={
                        "status": contract.get("status"),
                        "type": contract.get("type"),
                        "counterparty": counterparty.get("name"),
                        "owner": owner.get("email"),
                        "value": contract.get("value"),
                        "currency": contract.get("currency"),
                        "expiry_date": contract.get("expiry_date"),
                    },
                    raw_data=contract,
                )
            )

        return resources

    def _collect_template_resources(self) -> list[Resource]:
        """Collect template resources."""
        logger.info("Collecting SpotDraft template resources...")
        resources = []

        templates = self._paginate("/v1/templates")

        for template in templates:
            created_by = template.get("created_by", {}) or {}

            resources.append(
                Resource(
                    id=template.get("id", ""),
                    type="spotdraft_template",
                    provider="spotdraft",
                    region="global",
                    name=template.get("name", ""),
                    tags=[],
                    metadata={
                        "status": template.get("status"),
                        "category": template.get("category"),
                        "version": template.get("version"),
                        "created_by": created_by.get("email"),
                        "usage_count": template.get("usage_count", 0),
                    },
                    raw_data=template,
                )
            )

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting SpotDraft user resources...")
        resources = []

        users = self._paginate("/v1/users")

        for user in users:
            resources.append(
                Resource(
                    id=user.get("id", ""),
                    type="spotdraft_user",
                    provider="spotdraft",
                    region="global",
                    name=user.get("name", ""),
                    tags=[],
                    metadata={
                        "email": user.get("email"),
                        "role": user.get("role"),
                        "status": user.get("status"),
                        "mfa_enabled": user.get("mfa_enabled", False),
                        "last_login_at": user.get("last_login_at"),
                    },
                    raw_data=user,
                )
            )

        return resources

    def _collect_folder_resources(self) -> list[Resource]:
        """Collect folder resources."""
        logger.info("Collecting SpotDraft folder resources...")
        resources = []

        folders = self._paginate("/v1/folders")

        for folder in folders:
            resources.append(
                Resource(
                    id=folder.get("id", ""),
                    type="spotdraft_folder",
                    provider="spotdraft",
                    region="global",
                    name=folder.get("name", ""),
                    tags=[],
                    metadata={
                        "parent_id": folder.get("parent_id"),
                        "contract_count": folder.get("contract_count", 0),
                    },
                    raw_data=folder,
                )
            )

        return resources
