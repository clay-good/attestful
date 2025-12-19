"""
ISO 27001:2022 Certification Reporting Templates.

Provides reporting templates specific to ISO 27001:2022 certification:
- Statement of Applicability (SoA) generator
- Risk treatment plan template
- Internal audit report template
- Management review meeting minutes template
- ISMS scope documentation
- Control implementation status tracking

These templates follow the ISO 27001:2022 structure and produce
auditor-ready documentation for Stage 1 and Stage 2 certification audits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from attestful.core.logging import get_logger
from attestful.frameworks.iso27001.controls import (
    ISO_27001_CONTROLS,
    ISO_27001_VERSION,
    DOMAIN_NAMES,
    get_all_controls,
    get_controls_by_domain,
)

logger = get_logger("frameworks.iso27001.reports")


# =============================================================================
# Enums
# =============================================================================


class ApplicabilityStatus(str, Enum):
    """Control applicability status for SoA."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    PARTIALLY_APPLICABLE = "partially_applicable"


class ImplementationStatus(str, Enum):
    """Control implementation status."""

    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    PLANNED = "planned"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class RiskTreatmentOption(str, Enum):
    """Risk treatment options per ISO 27005."""

    MITIGATE = "mitigate"  # Apply controls to reduce risk
    ACCEPT = "accept"  # Accept the risk with management approval
    AVOID = "avoid"  # Avoid the risk by eliminating the source
    TRANSFER = "transfer"  # Transfer risk (e.g., insurance, outsourcing)


class AuditFindingType(str, Enum):
    """Types of audit findings."""

    MAJOR_NONCONFORMITY = "major_nonconformity"
    MINOR_NONCONFORMITY = "minor_nonconformity"
    OBSERVATION = "observation"
    OPPORTUNITY_FOR_IMPROVEMENT = "opportunity_for_improvement"
    CONFORMITY = "conformity"


class AuditFindingStatus(str, Enum):
    """Status of audit findings."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    VERIFIED = "verified"


# =============================================================================
# Statement of Applicability (SoA)
# =============================================================================


@dataclass
class SoAControlEntry:
    """
    Single control entry in the Statement of Applicability.

    Attributes:
        control_id: Annex A control ID (e.g., "A.5.1").
        control_title: Control title.
        domain: Control domain.
        applicability: Whether the control is applicable.
        justification: Justification for applicability decision.
        implementation_status: Current implementation status.
        implementation_description: How the control is implemented.
        responsible_party: Person/team responsible for the control.
        evidence_references: References to implementation evidence.
        risk_references: References to risk assessment findings.
        last_reviewed: Date of last review.
    """

    control_id: str
    control_title: str
    domain: str
    applicability: ApplicabilityStatus = ApplicabilityStatus.APPLICABLE
    justification: str = ""
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    implementation_description: str = ""
    responsible_party: str = ""
    evidence_references: list[str] = field(default_factory=list)
    risk_references: list[str] = field(default_factory=list)
    last_reviewed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "domain": self.domain,
            "applicability": self.applicability.value,
            "justification": self.justification,
            "implementation_status": self.implementation_status.value,
            "implementation_description": self.implementation_description,
            "responsible_party": self.responsible_party,
            "evidence_references": self.evidence_references,
            "risk_references": self.risk_references,
            "last_reviewed": self.last_reviewed.isoformat(),
        }


@dataclass
class StatementOfApplicability:
    """
    ISO 27001:2022 Statement of Applicability (SoA).

    The SoA is a required document that lists all Annex A controls,
    indicates whether each is applicable, and provides justification
    for exclusions.

    Attributes:
        organization_name: Name of the organization.
        scope: ISMS scope description.
        version: Document version number.
        created_date: Date the SoA was created.
        last_updated: Date of last update.
        approved_by: Person who approved the SoA.
        approval_date: Date of approval.
        controls: List of control entries.
        excluded_controls: List of excluded control IDs with justifications.
    """

    organization_name: str
    scope: str
    version: str = "1.0"
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: str = ""
    approval_date: datetime | None = None
    controls: list[SoAControlEntry] = field(default_factory=list)
    excluded_controls: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_type": "Statement of Applicability",
            "framework": "ISO 27001:2022",
            "organization_name": self.organization_name,
            "scope": self.scope,
            "version": self.version,
            "created_date": self.created_date.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "approved_by": self.approved_by,
            "approval_date": self.approval_date.isoformat() if self.approval_date else None,
            "total_controls": len(self.controls),
            "applicable_controls": sum(
                1 for c in self.controls
                if c.applicability == ApplicabilityStatus.APPLICABLE
            ),
            "excluded_controls_count": len(self.excluded_controls),
            "controls": [c.to_dict() for c in self.controls],
            "excluded_controls": self.excluded_controls,
        }


def generate_soa_template(
    organization_name: str,
    scope: str,
) -> StatementOfApplicability:
    """
    Generate a Statement of Applicability template with all controls.

    Args:
        organization_name: Name of the organization.
        scope: ISMS scope description.

    Returns:
        StatementOfApplicability with all controls initialized.
    """
    controls = []

    for control_id, control in sorted(ISO_27001_CONTROLS.items()):
        controls.append(SoAControlEntry(
            control_id=control_id,
            control_title=control.title,
            domain=control.domain,
            applicability=ApplicabilityStatus.APPLICABLE,
            justification="To be determined based on risk assessment",
            implementation_status=ImplementationStatus.NOT_IMPLEMENTED,
        ))

    return StatementOfApplicability(
        organization_name=organization_name,
        scope=scope,
        controls=controls,
    )


# =============================================================================
# Risk Treatment Plan
# =============================================================================


@dataclass
class RiskTreatmentEntry:
    """
    Single entry in the Risk Treatment Plan.

    Attributes:
        risk_id: Unique identifier for the risk.
        risk_description: Description of the information security risk.
        asset_affected: Asset(s) affected by the risk.
        threat_source: Source of the threat.
        vulnerability: Vulnerability being exploited.
        likelihood: Likelihood rating (1-5).
        impact: Impact rating (1-5).
        inherent_risk_level: Risk level before treatment.
        treatment_option: Selected risk treatment option.
        controls_applied: Annex A controls applied to treat the risk.
        residual_likelihood: Likelihood after treatment.
        residual_impact: Impact after treatment.
        residual_risk_level: Risk level after treatment.
        risk_owner: Person responsible for the risk.
        treatment_deadline: Target date for treatment completion.
        status: Current status of treatment.
        notes: Additional notes.
    """

    risk_id: str
    risk_description: str
    asset_affected: str = ""
    threat_source: str = ""
    vulnerability: str = ""
    likelihood: int = 3
    impact: int = 3
    inherent_risk_level: str = "medium"
    treatment_option: RiskTreatmentOption = RiskTreatmentOption.MITIGATE
    controls_applied: list[str] = field(default_factory=list)
    residual_likelihood: int = 2
    residual_impact: int = 2
    residual_risk_level: str = "low"
    risk_owner: str = ""
    treatment_deadline: datetime | None = None
    status: str = "planned"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "risk_id": self.risk_id,
            "risk_description": self.risk_description,
            "asset_affected": self.asset_affected,
            "threat_source": self.threat_source,
            "vulnerability": self.vulnerability,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "inherent_risk_level": self.inherent_risk_level,
            "treatment_option": self.treatment_option.value,
            "controls_applied": self.controls_applied,
            "residual_likelihood": self.residual_likelihood,
            "residual_impact": self.residual_impact,
            "residual_risk_level": self.residual_risk_level,
            "risk_owner": self.risk_owner,
            "treatment_deadline": self.treatment_deadline.isoformat() if self.treatment_deadline else None,
            "status": self.status,
            "notes": self.notes,
        }


@dataclass
class RiskTreatmentPlan:
    """
    ISO 27001:2022 Risk Treatment Plan.

    Documents how identified risks will be treated and maps
    controls to risks.

    Attributes:
        organization_name: Name of the organization.
        version: Document version.
        created_date: Date created.
        risk_assessment_reference: Reference to the risk assessment.
        risk_acceptance_criteria: Criteria for accepting residual risk.
        approved_by: Person who approved the plan.
        approval_date: Date of approval.
        risks: List of risk treatment entries.
    """

    organization_name: str
    version: str = "1.0"
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_assessment_reference: str = ""
    risk_acceptance_criteria: str = ""
    approved_by: str = ""
    approval_date: datetime | None = None
    risks: list[RiskTreatmentEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_type": "Risk Treatment Plan",
            "framework": "ISO 27001:2022",
            "organization_name": self.organization_name,
            "version": self.version,
            "created_date": self.created_date.isoformat(),
            "risk_assessment_reference": self.risk_assessment_reference,
            "risk_acceptance_criteria": self.risk_acceptance_criteria,
            "approved_by": self.approved_by,
            "approval_date": self.approval_date.isoformat() if self.approval_date else None,
            "total_risks": len(self.risks),
            "risks_by_treatment": {
                "mitigate": sum(1 for r in self.risks if r.treatment_option == RiskTreatmentOption.MITIGATE),
                "accept": sum(1 for r in self.risks if r.treatment_option == RiskTreatmentOption.ACCEPT),
                "avoid": sum(1 for r in self.risks if r.treatment_option == RiskTreatmentOption.AVOID),
                "transfer": sum(1 for r in self.risks if r.treatment_option == RiskTreatmentOption.TRANSFER),
            },
            "risks": [r.to_dict() for r in self.risks],
        }


def generate_risk_treatment_template(
    organization_name: str,
) -> RiskTreatmentPlan:
    """
    Generate a Risk Treatment Plan template.

    Args:
        organization_name: Name of the organization.

    Returns:
        Empty RiskTreatmentPlan template.
    """
    return RiskTreatmentPlan(
        organization_name=organization_name,
        risk_acceptance_criteria=(
            "Residual risks rated 'Low' or 'Medium' may be accepted with "
            "management approval. 'High' and 'Critical' residual risks must "
            "be treated or require executive-level acceptance."
        ),
    )


# =============================================================================
# Internal Audit Report
# =============================================================================


@dataclass
class AuditFinding:
    """
    Single finding from an internal audit.

    Attributes:
        finding_id: Unique identifier for the finding.
        finding_type: Type of finding (nonconformity, observation, etc.).
        clause_reference: ISO 27001 clause or Annex A control reference.
        finding_description: Detailed description of the finding.
        objective_evidence: Evidence supporting the finding.
        root_cause: Root cause analysis (for nonconformities).
        corrective_action: Corrective action required.
        responsible_party: Person responsible for corrective action.
        due_date: Due date for corrective action.
        status: Current status of the finding.
        closure_date: Date the finding was closed.
        verification_notes: Notes from verification of corrective action.
    """

    finding_id: str
    finding_type: AuditFindingType
    clause_reference: str
    finding_description: str
    objective_evidence: str = ""
    root_cause: str = ""
    corrective_action: str = ""
    responsible_party: str = ""
    due_date: datetime | None = None
    status: AuditFindingStatus = AuditFindingStatus.OPEN
    closure_date: datetime | None = None
    verification_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "clause_reference": self.clause_reference,
            "finding_description": self.finding_description,
            "objective_evidence": self.objective_evidence,
            "root_cause": self.root_cause,
            "corrective_action": self.corrective_action,
            "responsible_party": self.responsible_party,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "status": self.status.value,
            "closure_date": self.closure_date.isoformat() if self.closure_date else None,
            "verification_notes": self.verification_notes,
        }


@dataclass
class InternalAuditReport:
    """
    ISO 27001:2022 Internal Audit Report.

    Documents the results of an internal ISMS audit as required
    by Clause 9.2.

    Attributes:
        audit_id: Unique audit identifier.
        organization_name: Name of the organization.
        audit_title: Title of the audit.
        audit_objectives: Objectives of the audit.
        audit_scope: Scope of the audit.
        audit_criteria: Criteria used for the audit.
        audit_dates: Start and end dates of the audit.
        lead_auditor: Lead auditor name.
        audit_team: List of audit team members.
        areas_audited: Departments/processes audited.
        clauses_audited: ISO 27001 clauses audited.
        controls_audited: Annex A controls audited.
        findings: List of audit findings.
        audit_conclusion: Overall audit conclusion.
        recommendations: General recommendations.
        distribution_list: List of report recipients.
    """

    audit_id: str
    organization_name: str
    audit_title: str = "ISMS Internal Audit"
    audit_objectives: list[str] = field(default_factory=list)
    audit_scope: str = ""
    audit_criteria: list[str] = field(default_factory=lambda: ["ISO/IEC 27001:2022"])
    audit_dates: tuple[datetime, datetime] = field(
        default_factory=lambda: (datetime.now(timezone.utc), datetime.now(timezone.utc))
    )
    lead_auditor: str = ""
    audit_team: list[str] = field(default_factory=list)
    areas_audited: list[str] = field(default_factory=list)
    clauses_audited: list[str] = field(default_factory=list)
    controls_audited: list[str] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    audit_conclusion: str = ""
    recommendations: list[str] = field(default_factory=list)
    distribution_list: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_type": "Internal Audit Report",
            "framework": "ISO 27001:2022",
            "audit_id": self.audit_id,
            "organization_name": self.organization_name,
            "audit_title": self.audit_title,
            "audit_objectives": self.audit_objectives,
            "audit_scope": self.audit_scope,
            "audit_criteria": self.audit_criteria,
            "audit_start_date": self.audit_dates[0].isoformat(),
            "audit_end_date": self.audit_dates[1].isoformat(),
            "lead_auditor": self.lead_auditor,
            "audit_team": self.audit_team,
            "areas_audited": self.areas_audited,
            "clauses_audited": self.clauses_audited,
            "controls_audited": self.controls_audited,
            "findings_summary": {
                "total": len(self.findings),
                "major_nonconformities": sum(
                    1 for f in self.findings
                    if f.finding_type == AuditFindingType.MAJOR_NONCONFORMITY
                ),
                "minor_nonconformities": sum(
                    1 for f in self.findings
                    if f.finding_type == AuditFindingType.MINOR_NONCONFORMITY
                ),
                "observations": sum(
                    1 for f in self.findings
                    if f.finding_type == AuditFindingType.OBSERVATION
                ),
                "opportunities_for_improvement": sum(
                    1 for f in self.findings
                    if f.finding_type == AuditFindingType.OPPORTUNITY_FOR_IMPROVEMENT
                ),
            },
            "findings": [f.to_dict() for f in self.findings],
            "audit_conclusion": self.audit_conclusion,
            "recommendations": self.recommendations,
            "distribution_list": self.distribution_list,
        }


def generate_internal_audit_template(
    organization_name: str,
    audit_id: str | None = None,
) -> InternalAuditReport:
    """
    Generate an Internal Audit Report template.

    Args:
        organization_name: Name of the organization.
        audit_id: Optional audit ID (auto-generated if not provided).

    Returns:
        InternalAuditReport template.
    """
    return InternalAuditReport(
        audit_id=audit_id or f"IA-{datetime.now().strftime('%Y%m%d')}-{str(uuid4())[:8]}",
        organization_name=organization_name,
        audit_objectives=[
            "Verify conformity with ISO/IEC 27001:2022 requirements",
            "Verify conformity with organizational ISMS policies and procedures",
            "Assess the effectiveness of the ISMS",
            "Identify opportunities for improvement",
        ],
        clauses_audited=["4", "5", "6", "7", "8", "9", "10"],
    )


# =============================================================================
# Management Review Meeting Minutes
# =============================================================================


@dataclass
class ManagementReviewMinutes:
    """
    ISO 27001:2022 Management Review Meeting Minutes.

    Documents the management review of the ISMS as required by Clause 9.3.

    Attributes:
        meeting_id: Unique meeting identifier.
        organization_name: Name of the organization.
        meeting_date: Date of the meeting.
        attendees: List of meeting attendees.
        chair: Person chairing the meeting.
        previous_actions_status: Status of actions from previous review.
        changes_in_issues: Changes in internal/external issues.
        information_security_performance: Performance metrics review.
        feedback_from_interested_parties: Stakeholder feedback.
        risk_assessment_results: Summary of risk assessment results.
        audit_results: Summary of internal audit results.
        status_of_corrective_actions: Status of corrective actions.
        opportunities_for_improvement: Identified improvement opportunities.
        resource_needs: Resource requirements identified.
        decisions_made: Decisions made during the review.
        actions_assigned: Actions assigned with responsibilities.
        next_review_date: Date of next management review.
    """

    meeting_id: str
    organization_name: str
    meeting_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    attendees: list[dict[str, str]] = field(default_factory=list)
    chair: str = ""
    previous_actions_status: list[dict[str, Any]] = field(default_factory=list)
    changes_in_issues: str = ""
    information_security_performance: dict[str, Any] = field(default_factory=dict)
    feedback_from_interested_parties: str = ""
    risk_assessment_results: str = ""
    audit_results: str = ""
    status_of_corrective_actions: list[dict[str, Any]] = field(default_factory=list)
    opportunities_for_improvement: list[str] = field(default_factory=list)
    resource_needs: list[str] = field(default_factory=list)
    decisions_made: list[str] = field(default_factory=list)
    actions_assigned: list[dict[str, Any]] = field(default_factory=list)
    next_review_date: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_type": "Management Review Meeting Minutes",
            "framework": "ISO 27001:2022",
            "meeting_id": self.meeting_id,
            "organization_name": self.organization_name,
            "meeting_date": self.meeting_date.isoformat(),
            "attendees": self.attendees,
            "chair": self.chair,
            "clause_9.3_inputs": {
                "a_previous_actions_status": self.previous_actions_status,
                "b_changes_in_issues": self.changes_in_issues,
                "c_information_security_performance": self.information_security_performance,
                "d_feedback_from_interested_parties": self.feedback_from_interested_parties,
                "e_risk_assessment_results": self.risk_assessment_results,
                "f_audit_results": self.audit_results,
                "g_status_of_corrective_actions": self.status_of_corrective_actions,
                "h_opportunities_for_improvement": self.opportunities_for_improvement,
            },
            "clause_9.3_outputs": {
                "decisions_made": self.decisions_made,
                "actions_assigned": self.actions_assigned,
                "resource_needs": self.resource_needs,
            },
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
        }


def generate_management_review_template(
    organization_name: str,
    meeting_id: str | None = None,
) -> ManagementReviewMinutes:
    """
    Generate a Management Review Meeting Minutes template.

    Args:
        organization_name: Name of the organization.
        meeting_id: Optional meeting ID (auto-generated if not provided).

    Returns:
        ManagementReviewMinutes template.
    """
    return ManagementReviewMinutes(
        meeting_id=meeting_id or f"MR-{datetime.now().strftime('%Y%m%d')}-{str(uuid4())[:8]}",
        organization_name=organization_name,
        information_security_performance={
            "security_incidents": {"count": 0, "trend": "stable"},
            "policy_violations": {"count": 0, "trend": "stable"},
            "security_awareness_completion": {"percentage": 0, "target": 100},
            "vulnerability_remediation_time": {"average_days": 0, "target_days": 30},
            "audit_findings_closed": {"percentage": 0, "target": 100},
        },
    )


# =============================================================================
# Export Functions
# =============================================================================


def export_soa_to_json(soa: StatementOfApplicability, output_path: Path) -> None:
    """
    Export Statement of Applicability to JSON file.

    Args:
        soa: The SoA to export.
        output_path: Path to the output file.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(soa.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"Exported SoA to {output_path}")


def export_soa_to_markdown(soa: StatementOfApplicability) -> str:
    """
    Export Statement of Applicability to Markdown format.

    Args:
        soa: The SoA to export.

    Returns:
        Markdown-formatted string.
    """
    lines = [
        f"# Statement of Applicability",
        f"## {soa.organization_name}",
        "",
        f"**Framework:** ISO/IEC 27001:2022",
        f"**Version:** {soa.version}",
        f"**Scope:** {soa.scope}",
        f"**Created:** {soa.created_date.strftime('%Y-%m-%d')}",
        f"**Last Updated:** {soa.last_updated.strftime('%Y-%m-%d')}",
        "",
        "---",
        "",
    ]

    # Group controls by domain
    for domain_id, domain_name in DOMAIN_NAMES.items():
        domain_controls = [c for c in soa.controls if c.domain == domain_id]
        if not domain_controls:
            continue

        lines.append(f"## {domain_id}: {domain_name}")
        lines.append("")
        lines.append("| Control | Title | Applicable | Status | Justification |")
        lines.append("|---------|-------|------------|--------|---------------|")

        for control in domain_controls:
            app_icon = "✓" if control.applicability == ApplicabilityStatus.APPLICABLE else "✗"
            lines.append(
                f"| {control.control_id} | {control.control_title} | "
                f"{app_icon} | {control.implementation_status.value} | "
                f"{control.justification[:50]}{'...' if len(control.justification) > 50 else ''} |"
            )

        lines.append("")

    # Summary
    applicable = sum(1 for c in soa.controls if c.applicability == ApplicabilityStatus.APPLICABLE)
    implemented = sum(
        1 for c in soa.controls
        if c.implementation_status == ImplementationStatus.IMPLEMENTED
    )

    lines.extend([
        "---",
        "",
        "## Summary",
        "",
        f"- **Total Controls:** {len(soa.controls)}",
        f"- **Applicable Controls:** {applicable}",
        f"- **Excluded Controls:** {len(soa.excluded_controls)}",
        f"- **Implemented Controls:** {implemented}",
        f"- **Implementation Rate:** {round(implemented/applicable*100, 1) if applicable > 0 else 0}%",
    ])

    return "\n".join(lines)


def export_audit_report_to_json(report: InternalAuditReport, output_path: Path) -> None:
    """
    Export Internal Audit Report to JSON file.

    Args:
        report: The audit report to export.
        output_path: Path to the output file.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"Exported audit report to {output_path}")


# =============================================================================
# Statistics Functions
# =============================================================================


def get_report_statistics() -> dict[str, Any]:
    """
    Get statistics about ISO 27001 reporting capabilities.

    Returns:
        Dictionary with reporting statistics.
    """
    return {
        "framework": "ISO 27001:2022",
        "framework_version": ISO_27001_VERSION,
        "supported_templates": [
            "Statement of Applicability (SoA)",
            "Risk Treatment Plan",
            "Internal Audit Report",
            "Management Review Meeting Minutes",
        ],
        "total_controls": len(ISO_27001_CONTROLS),
        "domains": list(DOMAIN_NAMES.keys()),
        "export_formats": ["JSON", "Markdown"],
        "audit_finding_types": [t.value for t in AuditFindingType],
        "risk_treatment_options": [t.value for t in RiskTreatmentOption],
    }


__all__ = [
    # Enums
    "ApplicabilityStatus",
    "ImplementationStatus",
    "RiskTreatmentOption",
    "AuditFindingType",
    "AuditFindingStatus",
    # SoA classes
    "SoAControlEntry",
    "StatementOfApplicability",
    "generate_soa_template",
    # Risk Treatment Plan classes
    "RiskTreatmentEntry",
    "RiskTreatmentPlan",
    "generate_risk_treatment_template",
    # Internal Audit Report classes
    "AuditFinding",
    "InternalAuditReport",
    "generate_internal_audit_template",
    # Management Review classes
    "ManagementReviewMinutes",
    "generate_management_review_template",
    # Export functions
    "export_soa_to_json",
    "export_soa_to_markdown",
    "export_audit_report_to_json",
    # Statistics
    "get_report_statistics",
]
