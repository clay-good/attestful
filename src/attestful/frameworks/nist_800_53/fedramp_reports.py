"""
FedRAMP Reporting Templates.

Provides templates and generators for FedRAMP-specific documentation:
- System Security Plan (SSP) - Appendix A format
- Plan of Action and Milestones (POA&M)
- Monthly Continuous Monitoring Report
- Significant Change Request (SCR)

These templates follow FedRAMP Rev 5 requirements and can be exported
to OSCAL, JSON, or Markdown formats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


class FedRAMPDocumentType(str, Enum):
    """FedRAMP document types."""

    SSP = "ssp"
    POAM = "poam"
    CONTINUOUS_MONITORING = "continuous_monitoring"
    SIGNIFICANT_CHANGE_REQUEST = "scr"
    SAR = "sar"  # Security Assessment Report
    SAP = "sap"  # Security Assessment Plan


class ControlStatus(str, Enum):
    """Control implementation status."""

    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    PLANNED = "planned"
    ALTERNATIVE = "alternative"
    NOT_APPLICABLE = "not_applicable"


class POAMStatus(str, Enum):
    """POA&M item status."""

    OPEN = "open"
    CLOSED = "closed"
    DELAYED = "delayed"
    RISK_ACCEPTED = "risk_accepted"


class FindingSeverity(str, Enum):
    """Finding severity levels."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


# =============================================================================
# System Security Plan (SSP) Template
# =============================================================================


@dataclass
class SystemInfo:
    """System identification information."""

    system_name: str
    system_acronym: str = ""
    system_unique_id: str = ""
    authorization_boundary: str = ""
    system_description: str = ""
    system_type: str = ""  # Major Application, General Support System
    security_sensitivity_level: str = ""  # Low, Moderate, High
    deployment_model: str = ""  # Public Cloud, Private Cloud, Hybrid
    service_model: str = ""  # IaaS, PaaS, SaaS


@dataclass
class SystemOwner:
    """System owner and key personnel."""

    name: str
    organization: str
    email: str = ""
    phone: str = ""
    title: str = ""
    role: str = ""  # Authorizing Official, System Owner, ISSO, etc.


@dataclass
class ControlImplementation:
    """Individual control implementation details."""

    control_id: str
    status: ControlStatus
    implementation_description: str = ""
    responsible_role: str = ""
    implementation_date: date | None = None
    parameters: dict[str, str] = field(default_factory=dict)
    evidence_artifacts: list[str] = field(default_factory=list)
    inherited_from: str = ""  # For inherited controls
    common_control_provider: str = ""


@dataclass
class SSPTemplate:
    """
    FedRAMP System Security Plan template.

    Based on FedRAMP SSP Appendix A format (NIST SP 800-18 aligned).
    """

    # Section 1: System Information
    system_info: SystemInfo = field(default_factory=lambda: SystemInfo(system_name=""))

    # Section 2: System Owner and Key Personnel
    system_owner: SystemOwner | None = None
    authorizing_official: SystemOwner | None = None
    information_system_security_officer: SystemOwner | None = None
    key_personnel: list[SystemOwner] = field(default_factory=list)

    # Section 3: Authorization Boundary
    boundary_description: str = ""
    interconnections: list[dict[str, str]] = field(default_factory=list)
    data_flows: list[dict[str, str]] = field(default_factory=list)

    # Section 4: System Environment
    hardware_inventory: list[dict[str, Any]] = field(default_factory=list)
    software_inventory: list[dict[str, Any]] = field(default_factory=list)
    network_architecture: str = ""
    ports_protocols_services: list[dict[str, str]] = field(default_factory=list)

    # Section 5: Control Implementations
    control_implementations: dict[str, ControlImplementation] = field(default_factory=dict)

    # Metadata
    document_version: str = "1.0"
    last_updated: datetime = field(default_factory=datetime.now)
    baseline_level: str = "moderate"  # low, moderate, high
    fedramp_package_id: str = ""

    def get_control_implementation(self, control_id: str) -> ControlImplementation | None:
        """Get implementation details for a specific control."""
        return self.control_implementations.get(control_id.upper())

    def set_control_implementation(self, implementation: ControlImplementation) -> None:
        """Set or update a control implementation."""
        self.control_implementations[implementation.control_id.upper()] = implementation

    def get_implementation_summary(self) -> dict[str, int]:
        """Get summary counts by implementation status."""
        summary: dict[str, int] = {status.value: 0 for status in ControlStatus}
        for impl in self.control_implementations.values():
            summary[impl.status.value] += 1
        return summary


# =============================================================================
# Plan of Action and Milestones (POA&M) Template
# =============================================================================


@dataclass
class POAMItem:
    """Individual POA&M item/finding."""

    poam_id: str
    control_id: str
    finding_description: str
    severity: FindingSeverity = FindingSeverity.LOW
    status: POAMStatus = POAMStatus.OPEN
    weakness_source: str = ""  # Assessment, Self-Assessment, Continuous Monitoring
    weakness_description: str = ""
    remediation_plan: str = ""
    scheduled_completion_date: date | None = None
    actual_completion_date: date | None = None
    milestone_changes: list[dict[str, Any]] = field(default_factory=list)
    evidence_of_completion: str = ""
    risk_level: str = ""
    vendor_dependency: str = ""
    resource_requirements: str = ""
    comments: str = ""


@dataclass
class POAMTemplate:
    """
    FedRAMP Plan of Action and Milestones template.

    Tracks security weaknesses and remediation activities.
    """

    system_name: str = ""
    system_id: str = ""
    baseline_level: str = "moderate"
    items: list[POAMItem] = field(default_factory=list)

    # Metadata
    document_version: str = "1.0"
    last_updated: datetime = field(default_factory=datetime.now)
    prepared_by: str = ""
    approved_by: str = ""

    def add_item(self, item: POAMItem) -> None:
        """Add a POA&M item."""
        self.items.append(item)

    def get_item(self, poam_id: str) -> POAMItem | None:
        """Get a specific POA&M item."""
        for item in self.items:
            if item.poam_id == poam_id:
                return item
        return None

    def get_open_items(self) -> list[POAMItem]:
        """Get all open POA&M items."""
        return [item for item in self.items if item.status == POAMStatus.OPEN]

    def get_items_by_severity(self, severity: FindingSeverity) -> list[POAMItem]:
        """Get items by severity level."""
        return [item for item in self.items if item.severity == severity]

    def get_overdue_items(self, as_of: date | None = None) -> list[POAMItem]:
        """Get items past their scheduled completion date."""
        reference_date = as_of or date.today()
        return [
            item for item in self.items
            if item.status == POAMStatus.OPEN
            and item.scheduled_completion_date
            and item.scheduled_completion_date < reference_date
        ]

    def get_summary(self) -> dict[str, Any]:
        """Get POA&M summary statistics."""
        return {
            "total_items": len(self.items),
            "open_items": len(self.get_open_items()),
            "high_severity": len(self.get_items_by_severity(FindingSeverity.HIGH)),
            "moderate_severity": len(self.get_items_by_severity(FindingSeverity.MODERATE)),
            "low_severity": len(self.get_items_by_severity(FindingSeverity.LOW)),
            "overdue_items": len(self.get_overdue_items()),
            "by_status": {
                status.value: len([i for i in self.items if i.status == status])
                for status in POAMStatus
            },
        }


# =============================================================================
# Continuous Monitoring Report Template
# =============================================================================


@dataclass
class VulnerabilityScan:
    """Vulnerability scan result summary."""

    scan_date: date
    scan_tool: str
    total_hosts: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    moderate_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    false_positives: int = 0
    remediated_since_last: int = 0


@dataclass
class InventoryChange:
    """System inventory change record."""

    change_type: str  # Added, Removed, Modified
    component_type: str  # Hardware, Software, Network
    component_name: str
    change_date: date
    change_description: str = ""
    change_ticket: str = ""


@dataclass
class SecurityEvent:
    """Security event summary."""

    event_date: date
    event_type: str
    severity: str
    description: str
    response_actions: str = ""
    incident_ticket: str = ""


@dataclass
class ContinuousMonitoringReport:
    """
    FedRAMP Monthly Continuous Monitoring Report template.

    Tracks ongoing security status and compliance activities.
    """

    # Report identification
    system_name: str = ""
    system_id: str = ""
    reporting_period_start: date | None = None
    reporting_period_end: date | None = None

    # Executive summary
    executive_summary: str = ""
    overall_security_posture: str = ""  # Good, Fair, Poor

    # POA&M status
    poam_summary: dict[str, int] = field(default_factory=dict)
    new_poam_items: int = 0
    closed_poam_items: int = 0
    open_high_severity: int = 0

    # Vulnerability scanning
    vulnerability_scans: list[VulnerabilityScan] = field(default_factory=list)

    # Inventory
    inventory_changes: list[InventoryChange] = field(default_factory=list)

    # Security events
    security_events: list[SecurityEvent] = field(default_factory=list)

    # Control assessments
    controls_assessed: list[str] = field(default_factory=list)
    controls_findings: dict[str, str] = field(default_factory=dict)

    # Metadata
    document_version: str = "1.0"
    prepared_by: str = ""
    prepared_date: date | None = None
    reviewed_by: str = ""
    reviewed_date: date | None = None


# =============================================================================
# Significant Change Request (SCR) Template
# =============================================================================


@dataclass
class ImpactedControl:
    """Control impacted by a significant change."""

    control_id: str
    impact_description: str
    remediation_required: bool = False
    remediation_plan: str = ""


@dataclass
class SignificantChangeRequest:
    """
    FedRAMP Significant Change Request template.

    Documents changes that may affect the system's authorization.
    """

    # Change identification
    scr_id: str = ""
    system_name: str = ""
    system_id: str = ""
    change_title: str = ""
    change_description: str = ""

    # Change classification
    change_type: str = ""  # Architecture, Boundary, Network, Personnel, etc.
    is_significant: bool = True
    change_rationale: str = ""

    # Change details
    current_state: str = ""
    proposed_state: str = ""
    implementation_timeline: str = ""

    # Impact analysis
    impacted_controls: list[ImpactedControl] = field(default_factory=list)
    security_impact: str = ""
    risk_assessment: str = ""
    mitigation_measures: str = ""

    # Approvals
    requested_by: str = ""
    request_date: date | None = None
    isso_approval: str = ""
    isso_approval_date: date | None = None
    ao_approval: str = ""
    ao_approval_date: date | None = None

    # Status
    status: str = "pending"  # pending, approved, rejected, implemented

    def add_impacted_control(self, control: ImpactedControl) -> None:
        """Add an impacted control."""
        self.impacted_controls.append(control)


# =============================================================================
# Report Generation Functions
# =============================================================================


def create_ssp_template(
    system_name: str,
    baseline_level: str = "moderate",
    **kwargs: Any,
) -> SSPTemplate:
    """
    Create a new SSP template.

    Args:
        system_name: Name of the system
        baseline_level: FedRAMP baseline (low, moderate, high)
        **kwargs: Additional system information

    Returns:
        SSPTemplate instance
    """
    system_info = SystemInfo(
        system_name=system_name,
        security_sensitivity_level=baseline_level.capitalize(),
        **{k: v for k, v in kwargs.items() if hasattr(SystemInfo, k)},
    )

    return SSPTemplate(
        system_info=system_info,
        baseline_level=baseline_level,
    )


def create_poam_template(
    system_name: str,
    baseline_level: str = "moderate",
) -> POAMTemplate:
    """
    Create a new POA&M template.

    Args:
        system_name: Name of the system
        baseline_level: FedRAMP baseline (low, moderate, high)

    Returns:
        POAMTemplate instance
    """
    return POAMTemplate(
        system_name=system_name,
        baseline_level=baseline_level,
    )


def create_continuous_monitoring_report(
    system_name: str,
    period_start: date,
    period_end: date,
) -> ContinuousMonitoringReport:
    """
    Create a new continuous monitoring report.

    Args:
        system_name: Name of the system
        period_start: Reporting period start date
        period_end: Reporting period end date

    Returns:
        ContinuousMonitoringReport instance
    """
    return ContinuousMonitoringReport(
        system_name=system_name,
        reporting_period_start=period_start,
        reporting_period_end=period_end,
    )


def create_significant_change_request(
    system_name: str,
    change_title: str,
    change_description: str,
) -> SignificantChangeRequest:
    """
    Create a new significant change request.

    Args:
        system_name: Name of the system
        change_title: Brief title of the change
        change_description: Detailed description of the change

    Returns:
        SignificantChangeRequest instance
    """
    return SignificantChangeRequest(
        system_name=system_name,
        change_title=change_title,
        change_description=change_description,
        request_date=date.today(),
    )


def export_ssp_to_markdown(ssp: SSPTemplate) -> str:
    """
    Export SSP to Markdown format.

    Args:
        ssp: SSPTemplate instance

    Returns:
        Markdown string
    """
    lines = [
        f"# System Security Plan: {ssp.system_info.system_name}",
        "",
        f"**Document Version:** {ssp.document_version}",
        f"**Last Updated:** {ssp.last_updated.strftime('%Y-%m-%d')}",
        f"**FedRAMP Baseline:** {ssp.baseline_level.upper()}",
        "",
        "## 1. System Information",
        "",
        f"- **System Name:** {ssp.system_info.system_name}",
        f"- **System Acronym:** {ssp.system_info.system_acronym or 'N/A'}",
        f"- **Security Level:** {ssp.system_info.security_sensitivity_level}",
        f"- **Deployment Model:** {ssp.system_info.deployment_model or 'N/A'}",
        f"- **Service Model:** {ssp.system_info.service_model or 'N/A'}",
        "",
        "### System Description",
        "",
        ssp.system_info.system_description or "_No description provided._",
        "",
        "## 2. Authorization Boundary",
        "",
        ssp.boundary_description or "_Boundary description pending._",
        "",
        "## 3. Control Implementation Summary",
        "",
    ]

    summary = ssp.get_implementation_summary()
    lines.append("| Status | Count |")
    lines.append("|--------|-------|")
    for status, count in summary.items():
        lines.append(f"| {status.replace('_', ' ').title()} | {count} |")
    lines.append("")

    lines.append("## 4. Control Implementations")
    lines.append("")

    for control_id, impl in sorted(ssp.control_implementations.items()):
        lines.append(f"### {control_id}")
        lines.append("")
        lines.append(f"- **Status:** {impl.status.value.replace('_', ' ').title()}")
        lines.append(f"- **Responsible Role:** {impl.responsible_role or 'N/A'}")
        lines.append("")
        lines.append("**Implementation Description:**")
        lines.append("")
        lines.append(impl.implementation_description or "_No description provided._")
        lines.append("")

    return "\n".join(lines)


def export_poam_to_markdown(poam: POAMTemplate) -> str:
    """
    Export POA&M to Markdown format.

    Args:
        poam: POAMTemplate instance

    Returns:
        Markdown string
    """
    lines = [
        f"# Plan of Action and Milestones: {poam.system_name}",
        "",
        f"**Document Version:** {poam.document_version}",
        f"**Last Updated:** {poam.last_updated.strftime('%Y-%m-%d')}",
        f"**FedRAMP Baseline:** {poam.baseline_level.upper()}",
        "",
        "## Summary",
        "",
    ]

    summary = poam.get_summary()
    lines.append(f"- **Total Items:** {summary['total_items']}")
    lines.append(f"- **Open Items:** {summary['open_items']}")
    lines.append(f"- **High Severity:** {summary['high_severity']}")
    lines.append(f"- **Moderate Severity:** {summary['moderate_severity']}")
    lines.append(f"- **Low Severity:** {summary['low_severity']}")
    lines.append(f"- **Overdue Items:** {summary['overdue_items']}")
    lines.append("")

    lines.append("## POA&M Items")
    lines.append("")

    for item in poam.items:
        lines.append(f"### {item.poam_id}: {item.control_id}")
        lines.append("")
        lines.append(f"- **Severity:** {item.severity.value.upper()}")
        lines.append(f"- **Status:** {item.status.value.replace('_', ' ').title()}")
        lines.append(f"- **Scheduled Completion:** {item.scheduled_completion_date or 'TBD'}")
        lines.append("")
        lines.append("**Finding:**")
        lines.append("")
        lines.append(item.finding_description)
        lines.append("")
        lines.append("**Remediation Plan:**")
        lines.append("")
        lines.append(item.remediation_plan or "_Pending._")
        lines.append("")

    return "\n".join(lines)


__all__ = [
    # Enums
    "FedRAMPDocumentType",
    "ControlStatus",
    "POAMStatus",
    "FindingSeverity",
    # SSP classes
    "SystemInfo",
    "SystemOwner",
    "ControlImplementation",
    "SSPTemplate",
    # POA&M classes
    "POAMItem",
    "POAMTemplate",
    # Continuous Monitoring classes
    "VulnerabilityScan",
    "InventoryChange",
    "SecurityEvent",
    "ContinuousMonitoringReport",
    # SCR classes
    "ImpactedControl",
    "SignificantChangeRequest",
    # Factory functions
    "create_ssp_template",
    "create_poam_template",
    "create_continuous_monitoring_report",
    "create_significant_change_request",
    # Export functions
    "export_ssp_to_markdown",
    "export_poam_to_markdown",
]
