"""
ISO 27001:2022 Certification Audit Support.

Provides comprehensive support for ISO 27001 certification audits:
- Stage 1 (Documentation) audit package generation
- Stage 2 (Implementation) evidence collection workflow
- Nonconformity tracking and corrective action management
- Surveillance audit preparation
- Re-certification audit support

ISO 27001 Certification Process:
1. Stage 1 Audit: Documentation review (ISMS design adequacy)
2. Stage 2 Audit: Implementation verification (ISMS effectiveness)
3. Surveillance Audits: Annual verification (ongoing compliance)
4. Re-certification Audit: Full audit every 3 years (certification renewal)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
)
from attestful.frameworks.iso27001.reports import (
    AuditFinding,
    AuditFindingType,
    AuditFindingStatus,
    StatementOfApplicability,
    RiskTreatmentPlan,
    InternalAuditReport,
    ManagementReviewMinutes,
)

logger = get_logger("frameworks.iso27001.certification")


# =============================================================================
# Enums
# =============================================================================


class AuditStage(str, Enum):
    """ISO 27001 certification audit stages."""

    STAGE_1 = "stage_1"  # Documentation review
    STAGE_2 = "stage_2"  # Implementation audit
    SURVEILLANCE = "surveillance"  # Annual surveillance
    RECERTIFICATION = "recertification"  # 3-year re-certification


class NonconformityGrade(str, Enum):
    """Nonconformity classification grades."""

    MAJOR = "major"  # Absence or total breakdown of system element
    MINOR = "minor"  # Single lapse or partial compliance
    OPPORTUNITY = "opportunity_for_improvement"  # Not a nonconformity, but could be improved


class CorrectiveActionStatus(str, Enum):
    """Status of corrective actions."""

    IDENTIFIED = "identified"  # Nonconformity identified, action not yet planned
    PLANNED = "planned"  # Corrective action planned
    IN_PROGRESS = "in_progress"  # Implementation underway
    IMPLEMENTED = "implemented"  # Action completed, pending verification
    VERIFIED = "verified"  # Effectiveness verified
    CLOSED = "closed"  # Nonconformity closed


class EvidenceType(str, Enum):
    """Types of audit evidence."""

    DOCUMENT = "document"  # Policy, procedure, plan
    RECORD = "record"  # Log, report, form
    INTERVIEW = "interview"  # Staff interview transcript
    OBSERVATION = "observation"  # Auditor observation
    TECHNICAL = "technical"  # System configuration, scan results


class DocumentStatus(str, Enum):
    """Status of ISMS documents."""

    DRAFT = "draft"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REQUIRES_UPDATE = "requires_update"
    ARCHIVED = "archived"


# =============================================================================
# Stage 1 Documentation Package
# =============================================================================


@dataclass
class ISMSDocument:
    """
    Single ISMS document for Stage 1 audit.

    Attributes:
        document_id: Unique document identifier.
        title: Document title.
        document_type: Type of document.
        clause_reference: ISO 27001 clause(s) this document addresses.
        version: Document version.
        status: Current document status.
        owner: Document owner.
        approved_by: Approver name.
        approval_date: Date of approval.
        last_review_date: Date of last review.
        next_review_date: Date of next scheduled review.
        file_path: Path to the document file.
        description: Brief description of contents.
    """

    document_id: str
    title: str
    document_type: str
    clause_reference: list[str]
    version: str = "1.0"
    status: DocumentStatus = DocumentStatus.DRAFT
    owner: str = ""
    approved_by: str = ""
    approval_date: datetime | None = None
    last_review_date: datetime | None = None
    next_review_date: datetime | None = None
    file_path: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_id": self.document_id,
            "title": self.title,
            "document_type": self.document_type,
            "clause_reference": self.clause_reference,
            "version": self.version,
            "status": self.status.value,
            "owner": self.owner,
            "approved_by": self.approved_by,
            "approval_date": self.approval_date.isoformat() if self.approval_date else None,
            "last_review_date": self.last_review_date.isoformat() if self.last_review_date else None,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "file_path": self.file_path,
            "description": self.description,
        }


@dataclass
class Stage1DocumentationPackage:
    """
    Stage 1 documentation package for ISO 27001 certification.

    Stage 1 audit focuses on reviewing ISMS documentation to verify:
    - ISMS scope is defined
    - Information security policy exists
    - Risk assessment methodology is documented
    - Statement of Applicability is complete
    - Mandatory procedures exist
    - Internal audits and management reviews have been conducted

    Attributes:
        organization_name: Name of the organization.
        isms_scope: ISMS scope definition.
        certification_body: Name of the certification body.
        audit_date: Scheduled Stage 1 audit date.
        documents: List of ISMS documents.
        mandatory_documents_checklist: Checklist of required documents.
        readiness_assessment: Pre-audit readiness assessment.
    """

    organization_name: str
    isms_scope: str
    certification_body: str = ""
    audit_date: datetime | None = None
    documents: list[ISMSDocument] = field(default_factory=list)
    mandatory_documents_checklist: dict[str, bool] = field(default_factory=dict)
    readiness_assessment: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "package_type": "Stage 1 Documentation Package",
            "framework": "ISO 27001:2022",
            "organization_name": self.organization_name,
            "isms_scope": self.isms_scope,
            "certification_body": self.certification_body,
            "audit_date": self.audit_date.isoformat() if self.audit_date else None,
            "document_count": len(self.documents),
            "documents": [d.to_dict() for d in self.documents],
            "mandatory_documents_checklist": self.mandatory_documents_checklist,
            "mandatory_documents_complete": all(self.mandatory_documents_checklist.values()),
            "readiness_assessment": self.readiness_assessment,
        }


# Mandatory documents required for Stage 1 audit per ISO 27001:2022
MANDATORY_DOCUMENTS = {
    "scope": {
        "title": "ISMS Scope Statement",
        "clause": "4.3",
        "description": "Defines the boundaries and applicability of the ISMS",
    },
    "information_security_policy": {
        "title": "Information Security Policy",
        "clause": "5.2",
        "description": "Top-level policy approved by management",
    },
    "risk_assessment_methodology": {
        "title": "Risk Assessment Methodology",
        "clause": "6.1.2",
        "description": "Process for identifying and assessing information security risks",
    },
    "risk_assessment_report": {
        "title": "Risk Assessment Report",
        "clause": "6.1.2",
        "description": "Results of information security risk assessment",
    },
    "risk_treatment_plan": {
        "title": "Risk Treatment Plan",
        "clause": "6.1.3",
        "description": "Plan for treating identified risks",
    },
    "statement_of_applicability": {
        "title": "Statement of Applicability",
        "clause": "6.1.3",
        "description": "List of all Annex A controls with applicability decisions",
    },
    "information_security_objectives": {
        "title": "Information Security Objectives",
        "clause": "6.2",
        "description": "Measurable objectives consistent with the policy",
    },
    "competence_evidence": {
        "title": "Competence Records",
        "clause": "7.2",
        "description": "Evidence of required competence of persons",
    },
    "documented_information": {
        "title": "Document Control Procedure",
        "clause": "7.5",
        "description": "Procedure for managing documented information",
    },
    "operational_planning": {
        "title": "Operational Planning Documentation",
        "clause": "8.1",
        "description": "Planning and control of operations",
    },
    "risk_treatment_results": {
        "title": "Risk Treatment Results",
        "clause": "8.3",
        "description": "Results of information security risk treatment",
    },
    "monitoring_results": {
        "title": "Monitoring and Measurement Results",
        "clause": "9.1",
        "description": "Results of performance evaluation",
    },
    "internal_audit_program": {
        "title": "Internal Audit Program",
        "clause": "9.2",
        "description": "Program for conducting internal audits",
    },
    "internal_audit_results": {
        "title": "Internal Audit Reports",
        "clause": "9.2",
        "description": "Results of internal audits",
    },
    "management_review_results": {
        "title": "Management Review Minutes",
        "clause": "9.3",
        "description": "Records of management review outputs",
    },
    "corrective_action_results": {
        "title": "Corrective Action Records",
        "clause": "10.2",
        "description": "Records of nonconformities and corrective actions",
    },
}


def generate_stage1_package(
    organization_name: str,
    isms_scope: str,
    certification_body: str = "",
    audit_date: datetime | None = None,
) -> Stage1DocumentationPackage:
    """
    Generate a Stage 1 documentation package template.

    Args:
        organization_name: Name of the organization.
        isms_scope: ISMS scope definition.
        certification_body: Name of the certification body.
        audit_date: Scheduled Stage 1 audit date.

    Returns:
        Stage1DocumentationPackage with mandatory document checklist.
    """
    # Initialize mandatory documents checklist
    checklist = {doc_id: False for doc_id in MANDATORY_DOCUMENTS.keys()}

    # Create document templates for each mandatory document
    documents = []
    for doc_id, doc_info in MANDATORY_DOCUMENTS.items():
        documents.append(ISMSDocument(
            document_id=f"DOC-{doc_id.upper()}-001",
            title=doc_info["title"],
            document_type="mandatory",
            clause_reference=[doc_info["clause"]],
            description=doc_info["description"],
            status=DocumentStatus.DRAFT,
        ))

    # Initial readiness assessment
    readiness = {
        "assessment_date": datetime.now(timezone.utc).isoformat(),
        "mandatory_documents_ready": 0,
        "mandatory_documents_total": len(MANDATORY_DOCUMENTS),
        "readiness_percentage": 0,
        "gaps_identified": list(MANDATORY_DOCUMENTS.keys()),
        "recommendations": [
            "Complete all mandatory documents before scheduling Stage 1 audit",
            "Ensure all documents are approved by appropriate management",
            "Conduct at least one internal audit cycle",
            "Complete at least one management review",
        ],
    }

    return Stage1DocumentationPackage(
        organization_name=organization_name,
        isms_scope=isms_scope,
        certification_body=certification_body,
        audit_date=audit_date,
        documents=documents,
        mandatory_documents_checklist=checklist,
        readiness_assessment=readiness,
    )


# =============================================================================
# Stage 2 Evidence Collection
# =============================================================================


@dataclass
class AuditEvidence:
    """
    Single piece of audit evidence for Stage 2.

    Attributes:
        evidence_id: Unique evidence identifier.
        evidence_type: Type of evidence.
        control_reference: Control(s) this evidence supports.
        title: Evidence title.
        description: Description of the evidence.
        source: Source of the evidence.
        collection_date: Date evidence was collected.
        collected_by: Person who collected the evidence.
        file_path: Path to evidence file (if applicable).
        verification_status: Whether evidence has been verified.
        auditor_notes: Notes from the auditor.
    """

    evidence_id: str
    evidence_type: EvidenceType
    control_reference: list[str]
    title: str
    description: str = ""
    source: str = ""
    collection_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    collected_by: str = ""
    file_path: str = ""
    verification_status: str = "pending"
    auditor_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "control_reference": self.control_reference,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "collection_date": self.collection_date.isoformat(),
            "collected_by": self.collected_by,
            "file_path": self.file_path,
            "verification_status": self.verification_status,
            "auditor_notes": self.auditor_notes,
        }


@dataclass
class ControlEvidenceRequirement:
    """
    Evidence requirements for a specific control.

    Attributes:
        control_id: Annex A control ID.
        control_title: Control title.
        required_evidence_types: Types of evidence required.
        evidence_description: Description of expected evidence.
        interview_topics: Topics for staff interviews.
        observation_points: Points for auditor observation.
        collected_evidence: Evidence already collected.
        evidence_status: Overall evidence status.
    """

    control_id: str
    control_title: str
    required_evidence_types: list[EvidenceType]
    evidence_description: str = ""
    interview_topics: list[str] = field(default_factory=list)
    observation_points: list[str] = field(default_factory=list)
    collected_evidence: list[AuditEvidence] = field(default_factory=list)
    evidence_status: str = "incomplete"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "required_evidence_types": [t.value for t in self.required_evidence_types],
            "evidence_description": self.evidence_description,
            "interview_topics": self.interview_topics,
            "observation_points": self.observation_points,
            "collected_evidence": [e.to_dict() for e in self.collected_evidence],
            "evidence_count": len(self.collected_evidence),
            "evidence_status": self.evidence_status,
        }


@dataclass
class Stage2EvidenceWorkflow:
    """
    Stage 2 evidence collection workflow.

    Stage 2 audit verifies that the ISMS is effectively implemented by:
    - Reviewing implementation evidence
    - Interviewing staff
    - Observing processes in action
    - Testing controls

    Attributes:
        organization_name: Name of the organization.
        audit_date: Scheduled Stage 2 audit date.
        audit_duration: Expected audit duration in days.
        lead_auditor: Lead auditor name.
        audit_team: Audit team members.
        scope_controls: Controls in scope for the audit.
        evidence_requirements: Evidence requirements by control.
        interview_schedule: Planned interviews.
        observation_schedule: Planned observations.
        evidence_collection_status: Overall evidence collection status.
    """

    organization_name: str
    audit_date: datetime | None = None
    audit_duration: int = 3
    lead_auditor: str = ""
    audit_team: list[str] = field(default_factory=list)
    scope_controls: list[str] = field(default_factory=list)
    evidence_requirements: list[ControlEvidenceRequirement] = field(default_factory=list)
    interview_schedule: list[dict[str, Any]] = field(default_factory=list)
    observation_schedule: list[dict[str, Any]] = field(default_factory=list)
    evidence_collection_status: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        # Calculate evidence statistics
        total_controls = len(self.evidence_requirements)
        complete = sum(1 for e in self.evidence_requirements if e.evidence_status == "complete")
        partial = sum(1 for e in self.evidence_requirements if e.evidence_status == "partial")

        return {
            "workflow_type": "Stage 2 Evidence Collection",
            "framework": "ISO 27001:2022",
            "organization_name": self.organization_name,
            "audit_date": self.audit_date.isoformat() if self.audit_date else None,
            "audit_duration_days": self.audit_duration,
            "lead_auditor": self.lead_auditor,
            "audit_team": self.audit_team,
            "scope_controls_count": len(self.scope_controls),
            "evidence_requirements_count": total_controls,
            "evidence_requirements": [e.to_dict() for e in self.evidence_requirements],
            "interview_schedule": self.interview_schedule,
            "observation_schedule": self.observation_schedule,
            "evidence_statistics": {
                "total_controls": total_controls,
                "evidence_complete": complete,
                "evidence_partial": partial,
                "evidence_incomplete": total_controls - complete - partial,
                "readiness_percentage": round(complete / total_controls * 100, 1) if total_controls > 0 else 0,
            },
        }


# Evidence requirements by domain
DOMAIN_EVIDENCE_GUIDANCE = {
    "A.5": {  # Organizational controls
        "evidence_types": [EvidenceType.DOCUMENT, EvidenceType.RECORD],
        "description": "Policies, procedures, governance records, organizational charts",
        "interview_focus": ["Management", "Policy owners", "Compliance team"],
    },
    "A.6": {  # People controls
        "evidence_types": [EvidenceType.DOCUMENT, EvidenceType.RECORD, EvidenceType.INTERVIEW],
        "description": "HR records, training records, employment contracts, background check records",
        "interview_focus": ["HR team", "Line managers", "New employees"],
    },
    "A.7": {  # Physical controls
        "evidence_types": [EvidenceType.OBSERVATION, EvidenceType.RECORD],
        "description": "Physical access logs, CCTV footage, visitor logs, equipment inventories",
        "interview_focus": ["Facilities team", "Security guards", "Reception staff"],
    },
    "A.8": {  # Technological controls
        "evidence_types": [EvidenceType.TECHNICAL, EvidenceType.RECORD],
        "description": "System configurations, scan results, log files, technical documentation",
        "interview_focus": ["IT team", "Security operations", "System administrators"],
    },
}


def generate_stage2_workflow(
    organization_name: str,
    soa: StatementOfApplicability | None = None,
    audit_date: datetime | None = None,
) -> Stage2EvidenceWorkflow:
    """
    Generate a Stage 2 evidence collection workflow.

    Args:
        organization_name: Name of the organization.
        soa: Statement of Applicability (determines which controls to include).
        audit_date: Scheduled Stage 2 audit date.

    Returns:
        Stage2EvidenceWorkflow with evidence requirements.
    """
    evidence_requirements = []
    scope_controls = []

    # Determine controls in scope
    if soa:
        # Use SoA to determine applicable controls
        from attestful.frameworks.iso27001.reports import ApplicabilityStatus
        scope_controls = [
            c.control_id for c in soa.controls
            if c.applicability == ApplicabilityStatus.APPLICABLE
        ]
    else:
        # Include all controls
        scope_controls = list(ISO_27001_CONTROLS.keys())

    # Generate evidence requirements for each control
    for control_id in sorted(scope_controls):
        control = ISO_27001_CONTROLS.get(control_id)
        if not control:
            continue

        # Get domain-specific guidance
        domain = control.domain
        domain_guidance = DOMAIN_EVIDENCE_GUIDANCE.get(domain, {})

        evidence_types = domain_guidance.get("evidence_types", [EvidenceType.DOCUMENT])
        description = domain_guidance.get("description", "Evidence of control implementation")
        interview_focus = domain_guidance.get("interview_focus", [])

        evidence_requirements.append(ControlEvidenceRequirement(
            control_id=control_id,
            control_title=control.title,
            required_evidence_types=evidence_types,
            evidence_description=f"{control.title}: {description}",
            interview_topics=interview_focus,
            observation_points=_get_observation_points(control_id, domain),
            evidence_status="incomplete",
        ))

    # Generate interview schedule template
    interview_schedule = [
        {
            "interview_id": f"INT-{str(uuid4())[:8]}",
            "interviewee_role": "Information Security Manager",
            "topics": ["ISMS overview", "Risk management", "Security objectives"],
            "duration_minutes": 60,
            "scheduled_time": None,
        },
        {
            "interview_id": f"INT-{str(uuid4())[:8]}",
            "interviewee_role": "IT Manager",
            "topics": ["Technical controls", "Access management", "Change management"],
            "duration_minutes": 60,
            "scheduled_time": None,
        },
        {
            "interview_id": f"INT-{str(uuid4())[:8]}",
            "interviewee_role": "HR Manager",
            "topics": ["Employee screening", "Security awareness", "Termination process"],
            "duration_minutes": 45,
            "scheduled_time": None,
        },
        {
            "interview_id": f"INT-{str(uuid4())[:8]}",
            "interviewee_role": "Facilities Manager",
            "topics": ["Physical security", "Environmental controls", "Access control"],
            "duration_minutes": 45,
            "scheduled_time": None,
        },
    ]

    # Generate observation schedule template
    observation_schedule = [
        {
            "observation_id": f"OBS-{str(uuid4())[:8]}",
            "location": "Data Center / Server Room",
            "focus_areas": ["Physical access controls", "Environmental monitoring", "Equipment security"],
            "duration_minutes": 30,
            "scheduled_time": None,
        },
        {
            "observation_id": f"OBS-{str(uuid4())[:8]}",
            "location": "Office Areas",
            "focus_areas": ["Clean desk policy", "Screen locks", "Visitor management"],
            "duration_minutes": 30,
            "scheduled_time": None,
        },
        {
            "observation_id": f"OBS-{str(uuid4())[:8]}",
            "location": "Security Operations Center",
            "focus_areas": ["Monitoring activities", "Incident handling", "Log review"],
            "duration_minutes": 45,
            "scheduled_time": None,
        },
    ]

    return Stage2EvidenceWorkflow(
        organization_name=organization_name,
        audit_date=audit_date,
        scope_controls=scope_controls,
        evidence_requirements=evidence_requirements,
        interview_schedule=interview_schedule,
        observation_schedule=observation_schedule,
        evidence_collection_status={
            "started": False,
            "last_updated": None,
            "completion_percentage": 0,
        },
    )


def _get_observation_points(control_id: str, domain: str) -> list[str]:
    """Get observation points for a control based on its domain."""
    observation_points = {
        "A.5": ["Policy availability and awareness", "Governance meeting records"],
        "A.6": ["Security awareness activities", "HR process execution"],
        "A.7": ["Physical access control effectiveness", "Environmental controls in action"],
        "A.8": ["System operation and monitoring", "Technical control effectiveness"],
    }
    return observation_points.get(domain, ["General control implementation"])


# =============================================================================
# Nonconformity Tracking
# =============================================================================


@dataclass
class Nonconformity:
    """
    Nonconformity identified during audit.

    Attributes:
        nc_id: Unique nonconformity identifier.
        grade: Nonconformity grade (major, minor, OFI).
        audit_stage: Audit stage where identified.
        clause_reference: ISO 27001 clause reference.
        control_reference: Annex A control reference (if applicable).
        description: Description of the nonconformity.
        objective_evidence: Evidence of the nonconformity.
        identified_date: Date nonconformity was identified.
        identified_by: Auditor who identified it.
        root_cause: Root cause analysis.
        correction: Immediate correction taken.
        corrective_action: Corrective action to prevent recurrence.
        responsible_person: Person responsible for corrective action.
        target_date: Target date for completion.
        status: Current status.
        verification_date: Date of effectiveness verification.
        verification_evidence: Evidence of effectiveness.
        closure_date: Date nonconformity was closed.
        auditor_comments: Auditor comments on closure.
    """

    nc_id: str
    grade: NonconformityGrade
    audit_stage: AuditStage
    clause_reference: str
    control_reference: str = ""
    description: str = ""
    objective_evidence: str = ""
    identified_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    identified_by: str = ""
    root_cause: str = ""
    correction: str = ""
    corrective_action: str = ""
    responsible_person: str = ""
    target_date: datetime | None = None
    status: CorrectiveActionStatus = CorrectiveActionStatus.IDENTIFIED
    verification_date: datetime | None = None
    verification_evidence: str = ""
    closure_date: datetime | None = None
    auditor_comments: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nc_id": self.nc_id,
            "grade": self.grade.value,
            "audit_stage": self.audit_stage.value,
            "clause_reference": self.clause_reference,
            "control_reference": self.control_reference,
            "description": self.description,
            "objective_evidence": self.objective_evidence,
            "identified_date": self.identified_date.isoformat(),
            "identified_by": self.identified_by,
            "root_cause": self.root_cause,
            "correction": self.correction,
            "corrective_action": self.corrective_action,
            "responsible_person": self.responsible_person,
            "target_date": self.target_date.isoformat() if self.target_date else None,
            "status": self.status.value,
            "verification_date": self.verification_date.isoformat() if self.verification_date else None,
            "verification_evidence": self.verification_evidence,
            "closure_date": self.closure_date.isoformat() if self.closure_date else None,
            "auditor_comments": self.auditor_comments,
            "days_open": (datetime.now(timezone.utc) - self.identified_date).days if self.status != CorrectiveActionStatus.CLOSED else None,
        }


@dataclass
class CorrectiveActionPlan:
    """
    Corrective Action Plan for addressing nonconformities.

    Attributes:
        cap_id: Unique CAP identifier.
        organization_name: Name of the organization.
        audit_reference: Reference to the audit that identified nonconformities.
        created_date: Date the CAP was created.
        nonconformities: List of nonconformities to address.
        overall_status: Overall status of the CAP.
        next_review_date: Date of next review.
        approved_by: Person who approved the CAP.
        approval_date: Date of approval.
    """

    cap_id: str
    organization_name: str
    audit_reference: str = ""
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    nonconformities: list[Nonconformity] = field(default_factory=list)
    overall_status: str = "open"
    next_review_date: datetime | None = None
    approved_by: str = ""
    approval_date: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        # Calculate statistics
        total = len(self.nonconformities)
        major = sum(1 for nc in self.nonconformities if nc.grade == NonconformityGrade.MAJOR)
        minor = sum(1 for nc in self.nonconformities if nc.grade == NonconformityGrade.MINOR)
        closed = sum(1 for nc in self.nonconformities if nc.status == CorrectiveActionStatus.CLOSED)
        overdue = sum(
            1 for nc in self.nonconformities
            if nc.target_date and nc.target_date < datetime.now(timezone.utc)
            and nc.status not in [CorrectiveActionStatus.VERIFIED, CorrectiveActionStatus.CLOSED]
        )

        return {
            "document_type": "Corrective Action Plan",
            "framework": "ISO 27001:2022",
            "cap_id": self.cap_id,
            "organization_name": self.organization_name,
            "audit_reference": self.audit_reference,
            "created_date": self.created_date.isoformat(),
            "statistics": {
                "total_nonconformities": total,
                "major_nonconformities": major,
                "minor_nonconformities": minor,
                "opportunities_for_improvement": total - major - minor,
                "closed": closed,
                "open": total - closed,
                "overdue": overdue,
                "closure_rate": round(closed / total * 100, 1) if total > 0 else 0,
            },
            "nonconformities": [nc.to_dict() for nc in self.nonconformities],
            "overall_status": self.overall_status,
            "next_review_date": self.next_review_date.isoformat() if self.next_review_date else None,
            "approved_by": self.approved_by,
            "approval_date": self.approval_date.isoformat() if self.approval_date else None,
        }

    def add_nonconformity(self, nonconformity: Nonconformity) -> None:
        """Add a nonconformity to the plan."""
        self.nonconformities.append(nonconformity)
        self._update_status()

    def update_nonconformity_status(
        self,
        nc_id: str,
        new_status: CorrectiveActionStatus,
        **kwargs: Any,
    ) -> bool:
        """Update the status of a nonconformity."""
        for nc in self.nonconformities:
            if nc.nc_id == nc_id:
                nc.status = new_status
                for key, value in kwargs.items():
                    if hasattr(nc, key):
                        setattr(nc, key, value)
                self._update_status()
                return True
        return False

    def _update_status(self) -> None:
        """Update overall status based on nonconformity statuses."""
        if not self.nonconformities:
            self.overall_status = "empty"
            return

        all_closed = all(
            nc.status == CorrectiveActionStatus.CLOSED
            for nc in self.nonconformities
        )
        any_major_open = any(
            nc.grade == NonconformityGrade.MAJOR
            and nc.status != CorrectiveActionStatus.CLOSED
            for nc in self.nonconformities
        )

        if all_closed:
            self.overall_status = "closed"
        elif any_major_open:
            self.overall_status = "critical"
        else:
            self.overall_status = "open"


def create_corrective_action_plan(
    organization_name: str,
    audit_reference: str,
) -> CorrectiveActionPlan:
    """
    Create a new Corrective Action Plan.

    Args:
        organization_name: Name of the organization.
        audit_reference: Reference to the audit.

    Returns:
        Empty CorrectiveActionPlan.
    """
    return CorrectiveActionPlan(
        cap_id=f"CAP-{datetime.now().strftime('%Y%m%d')}-{str(uuid4())[:8]}",
        organization_name=organization_name,
        audit_reference=audit_reference,
        next_review_date=datetime.now(timezone.utc) + timedelta(days=30),
    )


def create_nonconformity(
    grade: NonconformityGrade,
    audit_stage: AuditStage,
    clause_reference: str,
    description: str,
    objective_evidence: str,
    identified_by: str,
    control_reference: str = "",
    target_days: int = 90,
) -> Nonconformity:
    """
    Create a new nonconformity record.

    Args:
        grade: Nonconformity grade.
        audit_stage: Audit stage where identified.
        clause_reference: ISO 27001 clause reference.
        description: Description of the nonconformity.
        objective_evidence: Evidence of the nonconformity.
        identified_by: Auditor who identified it.
        control_reference: Annex A control reference (optional).
        target_days: Days to complete corrective action (default 90).

    Returns:
        Nonconformity record.
    """
    # Adjust target days based on grade
    if grade == NonconformityGrade.MAJOR:
        target_days = min(target_days, 90)  # Major NCs must be addressed within 90 days
    elif grade == NonconformityGrade.MINOR:
        target_days = min(target_days, 180)  # Minor NCs typically have more time

    return Nonconformity(
        nc_id=f"NC-{datetime.now().strftime('%Y%m%d')}-{str(uuid4())[:8]}",
        grade=grade,
        audit_stage=audit_stage,
        clause_reference=clause_reference,
        control_reference=control_reference,
        description=description,
        objective_evidence=objective_evidence,
        identified_by=identified_by,
        target_date=datetime.now(timezone.utc) + timedelta(days=target_days),
    )


# =============================================================================
# Export Functions
# =============================================================================


def export_stage1_package(package: Stage1DocumentationPackage, output_path: Path) -> None:
    """Export Stage 1 documentation package to JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(package.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"Exported Stage 1 package to {output_path}")


def export_stage2_workflow(workflow: Stage2EvidenceWorkflow, output_path: Path) -> None:
    """Export Stage 2 evidence workflow to JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(workflow.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"Exported Stage 2 workflow to {output_path}")


def export_corrective_action_plan(cap: CorrectiveActionPlan, output_path: Path) -> None:
    """Export Corrective Action Plan to JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cap.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"Exported Corrective Action Plan to {output_path}")


def export_nonconformity_summary_markdown(cap: CorrectiveActionPlan) -> str:
    """
    Export nonconformity summary to Markdown format.

    Args:
        cap: Corrective Action Plan.

    Returns:
        Markdown-formatted summary.
    """
    lines = [
        "# Corrective Action Plan Summary",
        f"## {cap.organization_name}",
        "",
        f"**CAP ID:** {cap.cap_id}",
        f"**Audit Reference:** {cap.audit_reference}",
        f"**Created:** {cap.created_date.strftime('%Y-%m-%d')}",
        f"**Overall Status:** {cap.overall_status.upper()}",
        "",
        "---",
        "",
        "## Summary Statistics",
        "",
    ]

    # Statistics
    total = len(cap.nonconformities)
    major = sum(1 for nc in cap.nonconformities if nc.grade == NonconformityGrade.MAJOR)
    minor = sum(1 for nc in cap.nonconformities if nc.grade == NonconformityGrade.MINOR)
    closed = sum(1 for nc in cap.nonconformities if nc.status == CorrectiveActionStatus.CLOSED)

    lines.extend([
        f"- **Total Findings:** {total}",
        f"- **Major Nonconformities:** {major}",
        f"- **Minor Nonconformities:** {minor}",
        f"- **Opportunities for Improvement:** {total - major - minor}",
        f"- **Closed:** {closed}",
        f"- **Open:** {total - closed}",
        "",
        "---",
        "",
    ])

    # Major nonconformities first
    major_ncs = [nc for nc in cap.nonconformities if nc.grade == NonconformityGrade.MAJOR]
    if major_ncs:
        lines.extend([
            "## Major Nonconformities",
            "",
            "| ID | Clause | Description | Status | Target Date |",
            "|----|--------|-------------|--------|-------------|",
        ])
        for nc in major_ncs:
            target = nc.target_date.strftime('%Y-%m-%d') if nc.target_date else "TBD"
            desc = nc.description[:50] + "..." if len(nc.description) > 50 else nc.description
            lines.append(f"| {nc.nc_id} | {nc.clause_reference} | {desc} | {nc.status.value} | {target} |")
        lines.append("")

    # Minor nonconformities
    minor_ncs = [nc for nc in cap.nonconformities if nc.grade == NonconformityGrade.MINOR]
    if minor_ncs:
        lines.extend([
            "## Minor Nonconformities",
            "",
            "| ID | Clause | Description | Status | Target Date |",
            "|----|--------|-------------|--------|-------------|",
        ])
        for nc in minor_ncs:
            target = nc.target_date.strftime('%Y-%m-%d') if nc.target_date else "TBD"
            desc = nc.description[:50] + "..." if len(nc.description) > 50 else nc.description
            lines.append(f"| {nc.nc_id} | {nc.clause_reference} | {desc} | {nc.status.value} | {target} |")
        lines.append("")

    # OFIs
    ofis = [nc for nc in cap.nonconformities if nc.grade == NonconformityGrade.OPPORTUNITY]
    if ofis:
        lines.extend([
            "## Opportunities for Improvement",
            "",
            "| ID | Clause | Description | Status |",
            "|----|--------|-------------|--------|",
        ])
        for nc in ofis:
            desc = nc.description[:50] + "..." if len(nc.description) > 50 else nc.description
            lines.append(f"| {nc.nc_id} | {nc.clause_reference} | {desc} | {nc.status.value} |")
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# Statistics Functions
# =============================================================================


def get_certification_statistics() -> dict[str, Any]:
    """
    Get statistics about ISO 27001 certification support capabilities.

    Returns:
        Dictionary with certification statistics.
    """
    return {
        "framework": "ISO 27001:2022",
        "framework_version": ISO_27001_VERSION,
        "certification_stages": [s.value for s in AuditStage],
        "mandatory_documents_count": len(MANDATORY_DOCUMENTS),
        "mandatory_documents": list(MANDATORY_DOCUMENTS.keys()),
        "evidence_types_supported": [t.value for t in EvidenceType],
        "nonconformity_grades": [g.value for g in NonconformityGrade],
        "corrective_action_statuses": [s.value for s in CorrectiveActionStatus],
        "total_annex_a_controls": len(ISO_27001_CONTROLS),
        "domains": list(DOMAIN_NAMES.keys()),
        "features": [
            "Stage 1 documentation package generation",
            "Stage 2 evidence collection workflow",
            "Nonconformity tracking",
            "Corrective action management",
            "Audit evidence management",
            "Interview and observation scheduling",
            "Readiness assessment",
            "Export to JSON and Markdown",
        ],
    }


__all__ = [
    # Enums
    "AuditStage",
    "NonconformityGrade",
    "CorrectiveActionStatus",
    "EvidenceType",
    "DocumentStatus",
    # Stage 1 classes
    "ISMSDocument",
    "Stage1DocumentationPackage",
    "MANDATORY_DOCUMENTS",
    "generate_stage1_package",
    # Stage 2 classes
    "AuditEvidence",
    "ControlEvidenceRequirement",
    "Stage2EvidenceWorkflow",
    "DOMAIN_EVIDENCE_GUIDANCE",
    "generate_stage2_workflow",
    # Nonconformity tracking
    "Nonconformity",
    "CorrectiveActionPlan",
    "create_corrective_action_plan",
    "create_nonconformity",
    # Export functions
    "export_stage1_package",
    "export_stage2_workflow",
    "export_corrective_action_plan",
    "export_nonconformity_summary_markdown",
    # Statistics
    "get_certification_statistics",
]
