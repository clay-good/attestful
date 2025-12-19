"""
SOC 2 Trust Services Criteria Evidence Mappings.

Maps SOC 2 criteria (particularly the manual CC1-CC5 controls) to evidence types
that can be collected from various platforms. This enables semi-automated
compliance for organizational/governance controls.

Manual Controls (CC1-CC5) Coverage:
- CC1 (Control Environment): Requires organizational policies, HR evidence
- CC2 (Communication): Requires policy documentation, training records
- CC3 (Risk Assessment): Requires risk assessments, vulnerability scans
- CC4 (Monitoring): Requires audit logs, review records
- CC5 (Control Activities): Requires policy enforcement, access reviews

Evidence Sources:
- Okta: Identity, access, MFA enrollment
- Google Workspace: User management, security settings
- Jamf: Endpoint security, device compliance
- Jira: Issue tracking, change management
- GitLab/GitHub: Code review, CI/CD evidence
- Datadog: Monitoring, alerting evidence
- Zendesk: Support tickets, incident tracking
- Notion/Slab: Documentation, policies
- SpotDraft: Contracts, vendor agreements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any


class EvidenceRequirement(str, Enum):
    """How evidence satisfies a control requirement."""

    REQUIRED = "required"  # Must have this evidence
    RECOMMENDED = "recommended"  # Improves compliance posture
    OPTIONAL = "optional"  # Nice to have


class EvidenceFrequency(str, Enum):
    """How often evidence should be collected."""

    CONTINUOUS = "continuous"  # Real-time monitoring
    DAILY = "daily"  # Collected daily
    WEEKLY = "weekly"  # Collected weekly
    MONTHLY = "monthly"  # Collected monthly
    QUARTERLY = "quarterly"  # Collected quarterly
    ANNUALLY = "annually"  # Collected annually


@dataclass
class EvidenceSource:
    """
    Definition of an evidence source for a SOC 2 control.

    Attributes:
        evidence_type: Type of evidence (e.g., "okta_users").
        platforms: Platforms that can provide this evidence.
        requirement: Whether this evidence is required, recommended, or optional.
        frequency: How often the evidence should be collected.
        description: Human-readable description.
        collection_guidance: Instructions for collecting this evidence.
    """

    evidence_type: str
    platforms: list[str]
    requirement: EvidenceRequirement
    frequency: EvidenceFrequency
    description: str
    collection_guidance: str = ""


@dataclass
class SOC2EvidenceMapping:
    """
    Mapping of a SOC 2 criterion to required evidence.

    Attributes:
        criterion_id: SOC 2 criterion ID (e.g., "CC1.1").
        criterion_title: Title of the criterion.
        evidence_sources: List of evidence sources for this criterion.
        automation_status: Level of automation possible.
        manual_procedures: Manual steps required for compliance.
        auditor_guidance: Guidance for auditors reviewing this control.
    """

    criterion_id: str
    criterion_title: str
    evidence_sources: list[EvidenceSource] = field(default_factory=list)
    automation_status: str = "partial"  # automated, partial, manual
    manual_procedures: list[str] = field(default_factory=list)
    auditor_guidance: str = ""


# =============================================================================
# CC1 - Control Environment Evidence Mappings
# =============================================================================

CC1_EVIDENCE_MAPPINGS = [
    SOC2EvidenceMapping(
        criterion_id="CC1.1",
        criterion_title="COSO Principle 1: Demonstrates Commitment to Integrity and Ethical Values",
        evidence_sources=[
            EvidenceSource(
                evidence_type="policy_documents",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Code of conduct and ethics policies",
                collection_guidance="Export current code of conduct and ethics policy documents",
            ),
            EvidenceSource(
                evidence_type="training_records",
                platforms=["okta", "google_workspace"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Employee ethics training completion records",
                collection_guidance="Collect training completion records for ethics/compliance training",
            ),
            EvidenceSource(
                evidence_type="hr_acknowledgments",
                platforms=["notion", "docusign", "spotdraft"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Signed acknowledgments of code of conduct",
                collection_guidance="Collect signed policy acknowledgment records",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review code of conduct for currency and completeness",
            "Verify annual training completion rates exceed 95%",
            "Sample acknowledgment records for completeness",
        ],
        auditor_guidance="Request evidence of ethics training and policy acknowledgments",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC1.2",
        criterion_title="COSO Principle 2: Exercises Oversight Responsibility",
        evidence_sources=[
            EvidenceSource(
                evidence_type="board_minutes",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Board/committee meeting minutes",
                collection_guidance="Export board and committee meeting minutes",
            ),
            EvidenceSource(
                evidence_type="org_chart",
                platforms=["okta", "google_workspace"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Organizational structure documentation",
                collection_guidance="Generate org chart from directory service",
            ),
            EvidenceSource(
                evidence_type="role_definitions",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Role and responsibility definitions",
                collection_guidance="Export job descriptions and role matrices",
            ),
        ],
        automation_status="manual",
        manual_procedures=[
            "Review board meeting frequency and attendance",
            "Verify oversight committee charter is current",
            "Document reporting lines and accountability structure",
        ],
        auditor_guidance="Request board minutes showing security oversight discussions",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC1.3",
        criterion_title="COSO Principle 3: Establishes Structure, Authority, and Responsibility",
        evidence_sources=[
            EvidenceSource(
                evidence_type="okta_groups",
                platforms=["okta"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.MONTHLY,
                description="Group membership and role assignments",
                collection_guidance="Export Okta group memberships and assignments",
            ),
            EvidenceSource(
                evidence_type="role_matrix",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="RACI matrix or responsibility assignments",
                collection_guidance="Export role and responsibility documentation",
            ),
            EvidenceSource(
                evidence_type="security_team_structure",
                platforms=["okta", "google_workspace"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Security team organization and reporting",
                collection_guidance="Document security team structure",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Verify security function independence",
            "Review reporting structure for conflicts of interest",
            "Confirm adequate staffing for security operations",
        ],
        auditor_guidance="Request org charts showing security reporting lines",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC1.4",
        criterion_title="COSO Principle 4: Demonstrates Commitment to Competence",
        evidence_sources=[
            EvidenceSource(
                evidence_type="training_records",
                platforms=["okta", "google_workspace"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Security awareness training completion",
                collection_guidance="Export security training completion records",
            ),
            EvidenceSource(
                evidence_type="certification_records",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Professional certifications (CISSP, etc.)",
                collection_guidance="Collect certification records for security team",
            ),
            EvidenceSource(
                evidence_type="job_descriptions",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.OPTIONAL,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Job requirements and qualifications",
                collection_guidance="Export security role job descriptions",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Verify training curriculum is current",
            "Review security team qualifications",
            "Confirm competency assessment processes",
        ],
        auditor_guidance="Request training completion reports and competency assessments",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC1.5",
        criterion_title="COSO Principle 5: Enforces Accountability",
        evidence_sources=[
            EvidenceSource(
                evidence_type="performance_reviews",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Performance review records including security objectives",
                collection_guidance="Collect evidence of security in performance reviews",
            ),
            EvidenceSource(
                evidence_type="incident_records",
                platforms=["jira", "zendesk", "pagerduty"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Security incident and follow-up records",
                collection_guidance="Export incident records showing accountability",
            ),
            EvidenceSource(
                evidence_type="disciplinary_records",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.OPTIONAL,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Records of policy violation responses",
                collection_guidance="Document policy violation handling (anonymized)",
            ),
        ],
        automation_status="manual",
        manual_procedures=[
            "Review performance management process for security accountability",
            "Verify incident follow-up and lessons learned processes",
            "Confirm disciplinary procedures for policy violations",
        ],
        auditor_guidance="Request evidence of accountability enforcement",
    ),
]


# =============================================================================
# CC2 - Communication and Information Evidence Mappings
# =============================================================================

CC2_EVIDENCE_MAPPINGS = [
    SOC2EvidenceMapping(
        criterion_id="CC2.1",
        criterion_title="COSO Principle 13: Uses Relevant Information",
        evidence_sources=[
            EvidenceSource(
                evidence_type="security_metrics",
                platforms=["datadog", "cloudwatch"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Security dashboards and KPIs",
                collection_guidance="Export security metrics dashboards",
            ),
            EvidenceSource(
                evidence_type="vulnerability_reports",
                platforms=["inspector", "qualys", "trivy"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.WEEKLY,
                description="Vulnerability scan reports",
                collection_guidance="Collect vulnerability scanning reports",
            ),
            EvidenceSource(
                evidence_type="threat_intelligence",
                platforms=["guardduty", "securityhub"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Threat intelligence feeds and alerts",
                collection_guidance="Export threat detection findings",
            ),
        ],
        automation_status="automated",
        manual_procedures=[
            "Review information quality and timeliness",
            "Verify metrics alignment with risk objectives",
        ],
        auditor_guidance="Request security metrics and dashboards",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC2.2",
        criterion_title="COSO Principle 14: Communicates Internally",
        evidence_sources=[
            EvidenceSource(
                evidence_type="policy_distribution",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Evidence of policy distribution to employees",
                collection_guidance="Collect policy acknowledgment records",
            ),
            EvidenceSource(
                evidence_type="security_announcements",
                platforms=["slack", "email"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.MONTHLY,
                description="Security awareness communications",
                collection_guidance="Archive security announcements and newsletters",
            ),
            EvidenceSource(
                evidence_type="incident_communications",
                platforms=["pagerduty", "slack", "email"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Incident notification procedures",
                collection_guidance="Document incident communication processes",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review communication channels and effectiveness",
            "Verify policy accessibility for all employees",
            "Confirm incident communication procedures",
        ],
        auditor_guidance="Request evidence of internal security communications",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC2.3",
        criterion_title="COSO Principle 15: Communicates Externally",
        evidence_sources=[
            EvidenceSource(
                evidence_type="customer_agreements",
                platforms=["spotdraft", "docusign"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Customer contracts with security terms",
                collection_guidance="Export customer agreement templates",
            ),
            EvidenceSource(
                evidence_type="privacy_notices",
                platforms=["notion", "website"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Privacy policy and notices",
                collection_guidance="Archive current privacy notices",
            ),
            EvidenceSource(
                evidence_type="security_disclosures",
                platforms=["notion", "website"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Security practices disclosure (trust page)",
                collection_guidance="Archive security trust page content",
            ),
        ],
        automation_status="manual",
        manual_procedures=[
            "Review external communication processes",
            "Verify customer notification procedures",
            "Confirm regulatory reporting procedures",
        ],
        auditor_guidance="Request customer communication samples and breach notification procedures",
    ),
]


# =============================================================================
# CC3 - Risk Assessment Evidence Mappings
# =============================================================================

CC3_EVIDENCE_MAPPINGS = [
    SOC2EvidenceMapping(
        criterion_id="CC3.1",
        criterion_title="COSO Principle 6: Specifies Suitable Objectives",
        evidence_sources=[
            EvidenceSource(
                evidence_type="security_objectives",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Documented security objectives and goals",
                collection_guidance="Export security program objectives",
            ),
            EvidenceSource(
                evidence_type="risk_appetite",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Risk appetite and tolerance statements",
                collection_guidance="Document risk appetite thresholds",
            ),
        ],
        automation_status="manual",
        manual_procedures=[
            "Review security objectives alignment with business goals",
            "Verify risk tolerance levels are documented",
            "Confirm objectives are measurable and tracked",
        ],
        auditor_guidance="Request security strategy and objectives documentation",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC3.2",
        criterion_title="COSO Principle 7: Identifies and Analyzes Risks",
        evidence_sources=[
            EvidenceSource(
                evidence_type="risk_assessments",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Formal risk assessment documentation",
                collection_guidance="Export risk assessment reports",
            ),
            EvidenceSource(
                evidence_type="vulnerability_scans",
                platforms=["inspector", "qualys", "trivy"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.WEEKLY,
                description="Technical vulnerability assessments",
                collection_guidance="Collect vulnerability scan results",
            ),
            EvidenceSource(
                evidence_type="penetration_tests",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Penetration test reports",
                collection_guidance="Archive penetration test reports",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review risk assessment methodology",
            "Verify risk register is current",
            "Confirm third-party risk assessments",
        ],
        auditor_guidance="Request risk assessment reports and methodology",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC3.3",
        criterion_title="COSO Principle 8: Assesses Fraud Risk",
        evidence_sources=[
            EvidenceSource(
                evidence_type="fraud_risk_assessment",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Fraud risk assessment documentation",
                collection_guidance="Export fraud risk assessment",
            ),
            EvidenceSource(
                evidence_type="access_reviews",
                platforms=["okta", "aws_iam"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Access privilege reviews",
                collection_guidance="Collect access review records",
            ),
            EvidenceSource(
                evidence_type="segregation_of_duties",
                platforms=["okta", "notion"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Segregation of duties matrix",
                collection_guidance="Document SoD controls",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review fraud risk assessment for completeness",
            "Verify segregation of duties controls",
            "Confirm anti-fraud training completion",
        ],
        auditor_guidance="Request fraud risk assessment and SoD documentation",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC3.4",
        criterion_title="COSO Principle 9: Identifies and Analyzes Significant Change",
        evidence_sources=[
            EvidenceSource(
                evidence_type="change_records",
                platforms=["jira", "gitlab", "github"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Change management records",
                collection_guidance="Export change request records",
            ),
            EvidenceSource(
                evidence_type="architecture_reviews",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Architecture and design reviews",
                collection_guidance="Collect architecture review records",
            ),
            EvidenceSource(
                evidence_type="vendor_changes",
                platforms=["spotdraft", "notion"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Third-party/vendor change assessments",
                collection_guidance="Document vendor change impact assessments",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review significant change identification process",
            "Verify risk reassessment for major changes",
            "Confirm business process change procedures",
        ],
        auditor_guidance="Request evidence of change impact assessments",
    ),
]


# =============================================================================
# CC4 - Monitoring Activities Evidence Mappings
# =============================================================================

CC4_EVIDENCE_MAPPINGS = [
    SOC2EvidenceMapping(
        criterion_id="CC4.1",
        criterion_title="COSO Principle 16: Conducts Ongoing and/or Separate Evaluations",
        evidence_sources=[
            EvidenceSource(
                evidence_type="security_monitoring",
                platforms=["datadog", "cloudwatch", "securityhub"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Continuous security monitoring dashboards",
                collection_guidance="Export monitoring dashboard screenshots",
            ),
            EvidenceSource(
                evidence_type="audit_logs",
                platforms=["cloudtrail", "okta", "datadog"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Audit log collection and review",
                collection_guidance="Document log collection and review processes",
            ),
            EvidenceSource(
                evidence_type="control_testing",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Control testing and validation records",
                collection_guidance="Collect control testing evidence",
            ),
        ],
        automation_status="automated",
        manual_procedures=[
            "Review monitoring coverage and alerting",
            "Verify control testing procedures",
            "Confirm audit frequency is appropriate",
        ],
        auditor_guidance="Request monitoring dashboards and control testing records",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC4.2",
        criterion_title="COSO Principle 17: Evaluates and Communicates Deficiencies",
        evidence_sources=[
            EvidenceSource(
                evidence_type="finding_tracking",
                platforms=["jira", "notion"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Deficiency tracking and remediation",
                collection_guidance="Export finding remediation records",
            ),
            EvidenceSource(
                evidence_type="management_reports",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.MONTHLY,
                description="Management reporting on security posture",
                collection_guidance="Collect management security reports",
            ),
            EvidenceSource(
                evidence_type="board_reporting",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.QUARTERLY,
                description="Board-level security reporting",
                collection_guidance="Archive board security presentations",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review deficiency escalation procedures",
            "Verify timely remediation of findings",
            "Confirm management review and sign-off",
        ],
        auditor_guidance="Request deficiency tracking and remediation evidence",
    ),
]


# =============================================================================
# CC5 - Control Activities Evidence Mappings
# =============================================================================

CC5_EVIDENCE_MAPPINGS = [
    SOC2EvidenceMapping(
        criterion_id="CC5.1",
        criterion_title="COSO Principle 10: Selects and Develops Control Activities",
        evidence_sources=[
            EvidenceSource(
                evidence_type="control_inventory",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Control inventory and mapping",
                collection_guidance="Export control catalog documentation",
            ),
            EvidenceSource(
                evidence_type="security_policies",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Security policies and procedures",
                collection_guidance="Collect current security policies",
            ),
        ],
        automation_status="manual",
        manual_procedures=[
            "Review control selection rationale",
            "Verify controls address identified risks",
            "Confirm control design effectiveness",
        ],
        auditor_guidance="Request control inventory and risk-control mapping",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC5.2",
        criterion_title="COSO Principle 11: Selects and Develops General Controls over Technology",
        evidence_sources=[
            EvidenceSource(
                evidence_type="it_policies",
                platforms=["notion", "slab"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="IT policies and standards",
                collection_guidance="Export IT policies documentation",
            ),
            EvidenceSource(
                evidence_type="infrastructure_configs",
                platforms=["aws", "azure", "gcp", "terraform"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Infrastructure configuration evidence",
                collection_guidance="Collect infrastructure-as-code configs",
            ),
            EvidenceSource(
                evidence_type="change_management",
                platforms=["jira", "gitlab", "github"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="IT change management records",
                collection_guidance="Export change management tickets",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review IT general controls design",
            "Verify technology control implementation",
            "Confirm separation of environments",
        ],
        auditor_guidance="Request IT policies and infrastructure configurations",
    ),
    SOC2EvidenceMapping(
        criterion_id="CC5.3",
        criterion_title="COSO Principle 12: Deploys Through Policies and Procedures",
        evidence_sources=[
            EvidenceSource(
                evidence_type="policy_acknowledgments",
                platforms=["okta", "notion", "docusign"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Policy acknowledgment records",
                collection_guidance="Collect policy acknowledgment evidence",
            ),
            EvidenceSource(
                evidence_type="procedure_documentation",
                platforms=["notion", "slab", "confluence"],
                requirement=EvidenceRequirement.REQUIRED,
                frequency=EvidenceFrequency.ANNUALLY,
                description="Operational procedures documentation",
                collection_guidance="Export procedure runbooks",
            ),
            EvidenceSource(
                evidence_type="exception_tracking",
                platforms=["jira", "notion"],
                requirement=EvidenceRequirement.RECOMMENDED,
                frequency=EvidenceFrequency.CONTINUOUS,
                description="Policy exception tracking",
                collection_guidance="Document policy exception processes",
            ),
        ],
        automation_status="partial",
        manual_procedures=[
            "Review policy deployment effectiveness",
            "Verify procedure currency and accuracy",
            "Confirm exception handling processes",
        ],
        auditor_guidance="Request policy acknowledgments and exception records",
    ),
]


# =============================================================================
# Combined Mappings and Lookup Functions
# =============================================================================

# All CC1-CC5 evidence mappings
ALL_MANUAL_CONTROL_MAPPINGS: list[SOC2EvidenceMapping] = (
    CC1_EVIDENCE_MAPPINGS
    + CC2_EVIDENCE_MAPPINGS
    + CC3_EVIDENCE_MAPPINGS
    + CC4_EVIDENCE_MAPPINGS
    + CC5_EVIDENCE_MAPPINGS
)

# Index by criterion ID
MAPPING_INDEX: dict[str, SOC2EvidenceMapping] = {
    mapping.criterion_id: mapping for mapping in ALL_MANUAL_CONTROL_MAPPINGS
}


def get_evidence_mapping(criterion_id: str) -> SOC2EvidenceMapping | None:
    """
    Get the evidence mapping for a specific criterion.

    Args:
        criterion_id: The criterion ID (e.g., "CC1.1").

    Returns:
        The evidence mapping or None if not found.
    """
    return MAPPING_INDEX.get(criterion_id)


def get_mappings_by_category(category: str) -> list[SOC2EvidenceMapping]:
    """
    Get all evidence mappings for a category.

    Args:
        category: The category (CC1, CC2, CC3, CC4, CC5).

    Returns:
        List of evidence mappings for the category.
    """
    return [m for m in ALL_MANUAL_CONTROL_MAPPINGS if m.criterion_id.startswith(category)]


def get_required_evidence_types(criterion_id: str) -> list[str]:
    """
    Get the required evidence types for a criterion.

    Args:
        criterion_id: The criterion ID.

    Returns:
        List of required evidence type names.
    """
    mapping = get_evidence_mapping(criterion_id)
    if not mapping:
        return []

    return [
        source.evidence_type
        for source in mapping.evidence_sources
        if source.requirement == EvidenceRequirement.REQUIRED
    ]


def get_platforms_for_criterion(criterion_id: str) -> list[str]:
    """
    Get the platforms that can provide evidence for a criterion.

    Args:
        criterion_id: The criterion ID.

    Returns:
        List of platform names.
    """
    mapping = get_evidence_mapping(criterion_id)
    if not mapping:
        return []

    platforms: set[str] = set()
    for source in mapping.evidence_sources:
        platforms.update(source.platforms)

    return sorted(platforms)


def get_evidence_collection_schedule() -> dict[str, list[str]]:
    """
    Get evidence collection schedule organized by frequency.

    Returns:
        Dictionary mapping frequency to list of evidence types.
    """
    schedule: dict[str, list[str]] = {
        EvidenceFrequency.CONTINUOUS.value: [],
        EvidenceFrequency.DAILY.value: [],
        EvidenceFrequency.WEEKLY.value: [],
        EvidenceFrequency.MONTHLY.value: [],
        EvidenceFrequency.QUARTERLY.value: [],
        EvidenceFrequency.ANNUALLY.value: [],
    }

    seen: set[str] = set()
    for mapping in ALL_MANUAL_CONTROL_MAPPINGS:
        for source in mapping.evidence_sources:
            if source.evidence_type not in seen:
                seen.add(source.evidence_type)
                schedule[source.frequency.value].append(source.evidence_type)

    return schedule


def get_manual_control_statistics() -> dict[str, Any]:
    """
    Get statistics about manual control evidence mappings.

    Returns:
        Dictionary with mapping statistics.
    """
    total_mappings = len(ALL_MANUAL_CONTROL_MAPPINGS)

    # Count by category
    category_counts = {
        "CC1": len(CC1_EVIDENCE_MAPPINGS),
        "CC2": len(CC2_EVIDENCE_MAPPINGS),
        "CC3": len(CC3_EVIDENCE_MAPPINGS),
        "CC4": len(CC4_EVIDENCE_MAPPINGS),
        "CC5": len(CC5_EVIDENCE_MAPPINGS),
    }

    # Count by automation status
    automation_counts: dict[str, int] = {}
    for mapping in ALL_MANUAL_CONTROL_MAPPINGS:
        status = mapping.automation_status
        automation_counts[status] = automation_counts.get(status, 0) + 1

    # Count unique evidence types
    evidence_types: set[str] = set()
    for mapping in ALL_MANUAL_CONTROL_MAPPINGS:
        for source in mapping.evidence_sources:
            evidence_types.add(source.evidence_type)

    # Count unique platforms
    platforms: set[str] = set()
    for mapping in ALL_MANUAL_CONTROL_MAPPINGS:
        for source in mapping.evidence_sources:
            platforms.update(source.platforms)

    return {
        "total_mappings": total_mappings,
        "category_counts": category_counts,
        "automation_status": automation_counts,
        "unique_evidence_types": len(evidence_types),
        "evidence_types": sorted(evidence_types),
        "unique_platforms": len(platforms),
        "platforms": sorted(platforms),
    }


__all__ = [
    # Enums
    "EvidenceRequirement",
    "EvidenceFrequency",
    # Data classes
    "EvidenceSource",
    "SOC2EvidenceMapping",
    # Mapping lists
    "CC1_EVIDENCE_MAPPINGS",
    "CC2_EVIDENCE_MAPPINGS",
    "CC3_EVIDENCE_MAPPINGS",
    "CC4_EVIDENCE_MAPPINGS",
    "CC5_EVIDENCE_MAPPINGS",
    "ALL_MANUAL_CONTROL_MAPPINGS",
    "MAPPING_INDEX",
    # Lookup functions
    "get_evidence_mapping",
    "get_mappings_by_category",
    "get_required_evidence_types",
    "get_platforms_for_criterion",
    "get_evidence_collection_schedule",
    "get_manual_control_statistics",
]
