"""
SOC 2 Type II Audit Reporting Templates.

Provides reporting templates specific to SOC 2 Type II audits:
- Type II audit evidence package generation
- Management assertion template
- Description of controls (system description)
- Testing results summary
- Control matrix with evidence mapping
- Exception and deviation reporting

These templates follow the AICPA Trust Services Criteria structure
and produce auditor-ready documentation.
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
from attestful.frameworks.soc2.controls import SOC2_CONTROLS, get_all_controls
from attestful.frameworks.soc2.evidence_mappings import (
    ALL_MANUAL_CONTROL_MAPPINGS,
    get_evidence_mapping,
    get_manual_control_statistics,
)

logger = get_logger("frameworks.soc2.reports")


class TestResult(str, Enum):
    """Test result classification for SOC 2 controls."""

    OPERATING_EFFECTIVELY = "operating_effectively"
    EXCEPTION_NOTED = "exception_noted"
    DEVIATION_NOTED = "deviation_noted"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"


class ControlStatus(str, Enum):
    """Control implementation status."""

    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ControlTestResult:
    """
    Result of testing a specific SOC 2 control.

    Attributes:
        control_id: The Trust Services Criterion ID (e.g., "CC6.1").
        control_title: Title of the criterion.
        test_result: Result of the control test.
        sample_size: Number of items sampled.
        exceptions_count: Number of exceptions identified.
        test_procedures: Description of testing procedures performed.
        evidence_references: References to evidence collected.
        findings: Description of findings or exceptions.
        recommendations: Recommendations for remediation.
        tested_by: Person/system that performed the test.
        tested_date: Date testing was performed.
    """

    control_id: str
    control_title: str
    test_result: TestResult = TestResult.NOT_TESTED
    sample_size: int = 0
    exceptions_count: int = 0
    test_procedures: list[str] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    findings: str = ""
    recommendations: str = ""
    tested_by: str = "Attestful Automated Testing"
    tested_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "test_result": self.test_result.value,
            "sample_size": self.sample_size,
            "exceptions_count": self.exceptions_count,
            "test_procedures": self.test_procedures,
            "evidence_references": self.evidence_references,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "tested_by": self.tested_by,
            "tested_date": self.tested_date.isoformat(),
        }


@dataclass
class ManagementAssertion:
    """
    SOC 2 Management Assertion template.

    The management assertion is a formal statement by management
    regarding the fairness of the presentation of the description
    and the suitability of the design and operating effectiveness
    of controls.

    Attributes:
        organization_name: Name of the service organization.
        system_name: Name of the system being assessed.
        assertion_date: Date of the assertion.
        period_start: Start of the assessment period.
        period_end: End of the assessment period.
        categories_in_scope: Trust Services Categories in scope.
        responsible_executive: Name and title of responsible executive.
        description_criteria: Statement about description criteria.
        control_design: Statement about control design suitability.
        control_effectiveness: Statement about operating effectiveness.
        complementary_user_controls: List of user entity controls.
        subservice_organizations: List of subservice organizations used.
    """

    organization_name: str
    system_name: str
    assertion_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    categories_in_scope: list[str] = field(default_factory=lambda: ["Security"])
    responsible_executive: str = ""
    description_criteria: str = ""
    control_design: str = ""
    control_effectiveness: str = ""
    complementary_user_controls: list[str] = field(default_factory=list)
    subservice_organizations: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "organization_name": self.organization_name,
            "system_name": self.system_name,
            "assertion_date": self.assertion_date.isoformat(),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "categories_in_scope": self.categories_in_scope,
            "responsible_executive": self.responsible_executive,
            "description_criteria": self.description_criteria,
            "control_design": self.control_design,
            "control_effectiveness": self.control_effectiveness,
            "complementary_user_controls": self.complementary_user_controls,
            "subservice_organizations": self.subservice_organizations,
        }

    def generate_text(self) -> str:
        """Generate the management assertion text."""
        categories_text = ", ".join(self.categories_in_scope)
        period_text = (
            f"{self.period_start.strftime('%B %d, %Y')} through "
            f"{self.period_end.strftime('%B %d, %Y')}"
        )

        text = f"""
MANAGEMENT'S ASSERTION

{self.organization_name} ("the Company") has prepared the accompanying description of
{self.system_name} (the "system") throughout the period {period_text}
(the "description") based on the criteria set forth in TSP Section 100, Trust Services
Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy
(AICPA, 2017 Trust Services Criteria).

The description is intended to provide report users with information about the system that
may be useful when assessing the risks arising from interactions with {self.organization_name}'s
system, particularly information about system controls that {self.organization_name} has
designed, implemented, and operated to provide reasonable assurance that its service
commitments and system requirements were achieved based on the trust services criteria
relevant to {categories_text} set forth in TSP Section 100.

{self.organization_name} confirms, to the best of its knowledge and belief, that:

a. The description fairly presents the system that was designed and implemented throughout
   the period {period_text}, based on the following criteria:

   i.   The description contains all the information necessary for report users to understand
        the system;
   ii.  The description does not omit or distort information relevant to the system in scope;
   iii. The description includes relevant details of changes to the system during the period
        covered.

b. The controls stated in the description were suitably designed throughout the period
   {period_text} to provide reasonable assurance that {self.organization_name}'s
   service commitments and system requirements would be achieved based on the applicable
   trust services criteria, if the controls operated effectively throughout that period,
   and user entities applied the complementary user entity controls contemplated in the
   design of {self.organization_name}'s controls throughout that period.

c. The controls stated in the description operated effectively throughout the period
   {period_text} to provide reasonable assurance that {self.organization_name}'s
   service commitments and system requirements were achieved based on the applicable trust
   services criteria, if complementary user entity controls contemplated in the design of
   {self.organization_name}'s controls operated effectively throughout that period.

"""
        if self.complementary_user_controls:
            text += "COMPLEMENTARY USER ENTITY CONTROLS\n\n"
            text += (
                "The following complementary user entity controls should be in place at "
                "user entities:\n\n"
            )
            for i, control in enumerate(self.complementary_user_controls, 1):
                text += f"  {i}. {control}\n"
            text += "\n"

        if self.subservice_organizations:
            text += "SUBSERVICE ORGANIZATIONS\n\n"
            text += (
                "The description includes only the controls of the service organization "
                "and excludes the controls of the following subservice organizations:\n\n"
            )
            for subservice in self.subservice_organizations:
                text += f"  - {subservice.get('name', 'Unknown')}: {subservice.get('description', '')}\n"
            text += "\n"

        text += f"""
{self.responsible_executive}
{self.organization_name}
{self.assertion_date.strftime('%B %d, %Y')}
"""
        return text


@dataclass
class SystemDescription:
    """
    SOC 2 System Description template.

    Provides the structure for documenting the system description
    as required for SOC 2 Type II reports.

    Attributes:
        organization_name: Name of the service organization.
        system_name: Name of the system.
        services_provided: Description of services.
        principal_service_commitments: Key service commitments.
        system_requirements: System requirements to meet commitments.
        components: System components (infrastructure, software, people, etc.).
        boundaries: System boundaries and scope.
        trust_services_categories: Categories in scope.
        control_environment: Description of control environment.
        risk_assessment: Risk assessment overview.
        information_communication: Information and communication systems.
        monitoring: Monitoring activities.
        control_activities: Control activities by criterion.
    """

    organization_name: str
    system_name: str
    services_provided: str = ""
    principal_service_commitments: list[str] = field(default_factory=list)
    system_requirements: list[str] = field(default_factory=list)
    components: dict[str, str] = field(default_factory=dict)
    boundaries: dict[str, Any] = field(default_factory=dict)
    trust_services_categories: list[str] = field(default_factory=lambda: ["Security"])
    control_environment: str = ""
    risk_assessment: str = ""
    information_communication: str = ""
    monitoring: str = ""
    control_activities: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "organization_name": self.organization_name,
            "system_name": self.system_name,
            "services_provided": self.services_provided,
            "principal_service_commitments": self.principal_service_commitments,
            "system_requirements": self.system_requirements,
            "components": self.components,
            "boundaries": self.boundaries,
            "trust_services_categories": self.trust_services_categories,
            "control_environment": self.control_environment,
            "risk_assessment": self.risk_assessment,
            "information_communication": self.information_communication,
            "monitoring": self.monitoring,
            "control_activities": self.control_activities,
        }


@dataclass
class TestResultsSummary:
    """
    SOC 2 Testing Results Summary.

    Aggregates test results across all controls for the audit period.

    Attributes:
        report_id: Unique report identifier.
        period_start: Start of audit period.
        period_end: End of audit period.
        test_results: Individual control test results.
        overall_opinion: Overall audit opinion.
        total_controls: Total controls tested.
        effective_controls: Controls operating effectively.
        exceptions_noted: Controls with exceptions.
        deviations_noted: Controls with deviations.
    """

    report_id: str = field(default_factory=lambda: str(uuid4()))
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    test_results: list[ControlTestResult] = field(default_factory=list)
    overall_opinion: str = ""
    total_controls: int = 0
    effective_controls: int = 0
    exceptions_noted: int = 0
    deviations_noted: int = 0

    def calculate_statistics(self) -> None:
        """Calculate summary statistics from test results."""
        self.total_controls = len(self.test_results)
        self.effective_controls = sum(
            1 for r in self.test_results
            if r.test_result == TestResult.OPERATING_EFFECTIVELY
        )
        self.exceptions_noted = sum(
            1 for r in self.test_results
            if r.test_result == TestResult.EXCEPTION_NOTED
        )
        self.deviations_noted = sum(
            1 for r in self.test_results
            if r.test_result == TestResult.DEVIATION_NOTED
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        self.calculate_statistics()
        return {
            "report_id": self.report_id,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "test_results": [r.to_dict() for r in self.test_results],
            "summary": {
                "overall_opinion": self.overall_opinion,
                "total_controls": self.total_controls,
                "effective_controls": self.effective_controls,
                "exceptions_noted": self.exceptions_noted,
                "deviations_noted": self.deviations_noted,
                "effectiveness_rate": (
                    round(self.effective_controls / self.total_controls * 100, 1)
                    if self.total_controls > 0 else 0
                ),
            },
        }


@dataclass
class SOC2EvidencePackage:
    """
    SOC 2 Type II Audit Evidence Package.

    Comprehensive package of evidence for SOC 2 Type II audit,
    including all components required by auditors.

    Attributes:
        package_id: Unique package identifier.
        organization_name: Name of the service organization.
        system_name: Name of the system.
        period_start: Start of audit period.
        period_end: End of audit period.
        management_assertion: Management assertion document.
        system_description: System description document.
        test_results: Testing results summary.
        control_matrix: Control matrix with evidence mapping.
        automated_check_results: Results from automated compliance checks.
        evidence_inventory: Inventory of all evidence collected.
        generated_at: When the package was generated.
    """

    package_id: str = field(default_factory=lambda: str(uuid4()))
    organization_name: str = ""
    system_name: str = ""
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    management_assertion: ManagementAssertion | None = None
    system_description: SystemDescription | None = None
    test_results: TestResultsSummary | None = None
    control_matrix: list[dict[str, Any]] = field(default_factory=list)
    automated_check_results: list[dict[str, Any]] = field(default_factory=list)
    evidence_inventory: list[dict[str, Any]] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "package_id": self.package_id,
            "organization_name": self.organization_name,
            "system_name": self.system_name,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "management_assertion": (
                self.management_assertion.to_dict() if self.management_assertion else None
            ),
            "system_description": (
                self.system_description.to_dict() if self.system_description else None
            ),
            "test_results": (
                self.test_results.to_dict() if self.test_results else None
            ),
            "control_matrix": self.control_matrix,
            "automated_check_results_count": len(self.automated_check_results),
            "evidence_inventory_count": len(self.evidence_inventory),
            "generated_at": self.generated_at.isoformat(),
        }


# =============================================================================
# Report Generation Functions
# =============================================================================


def generate_control_matrix() -> list[dict[str, Any]]:
    """
    Generate a control matrix showing all Trust Services Criteria
    with their evidence mappings and automation status.

    Returns:
        List of control matrix entries.
    """
    matrix = []
    all_controls = get_all_controls()

    for control in all_controls:
        # Get evidence mapping if available (CC1-CC5)
        evidence_mapping = get_evidence_mapping(control.id)

        entry = {
            "control_id": control.id,
            "control_title": control.title,
            "category": control.category,
            "description": control.description,
            "automation_status": evidence_mapping.automation_status if evidence_mapping else "automated",
            "evidence_sources": [],
            "manual_procedures": [],
            "auditor_guidance": "",
        }

        if evidence_mapping:
            entry["evidence_sources"] = [
                {
                    "type": source.evidence_type,
                    "platforms": source.platforms,
                    "requirement": source.requirement.value,
                    "frequency": source.frequency.value,
                }
                for source in evidence_mapping.evidence_sources
            ]
            entry["manual_procedures"] = evidence_mapping.manual_procedures
            entry["auditor_guidance"] = evidence_mapping.auditor_guidance

        matrix.append(entry)

    return matrix


def generate_testing_procedures() -> dict[str, list[str]]:
    """
    Generate testing procedures for each Trust Services Criterion.

    Returns:
        Dictionary mapping control IDs to testing procedures.
    """
    procedures: dict[str, list[str]] = {}

    # Technical controls (CC6-CC9) - automated testing
    technical_procedures = [
        "Execute automated compliance checks against cloud resources",
        "Review check results for passing/failing status",
        "Sample resources for manual verification of automation accuracy",
        "Document any exceptions or false positives",
    ]

    # Manual controls (CC1-CC5) - evidence-based testing
    for mapping in ALL_MANUAL_CONTROL_MAPPINGS:
        control_procedures = [
            f"Collect {source.evidence_type} from {', '.join(source.platforms)}"
            for source in mapping.evidence_sources
            if source.requirement.value == "required"
        ]
        control_procedures.extend(mapping.manual_procedures)
        procedures[mapping.criterion_id] = control_procedures

    # Add procedures for technical controls
    for control in get_all_controls():
        if control.id.startswith(("CC6", "CC7", "CC8", "CC9", "A", "PI", "C", "P")):
            if control.id not in procedures:
                procedures[control.id] = technical_procedures.copy()

    return procedures


def generate_evidence_package(
    organization_name: str,
    system_name: str,
    period_start: datetime,
    period_end: datetime,
    check_results: list[dict[str, Any]] | None = None,
    collected_evidence: list[dict[str, Any]] | None = None,
) -> SOC2EvidencePackage:
    """
    Generate a complete SOC 2 Type II evidence package.

    Args:
        organization_name: Name of the service organization.
        system_name: Name of the system being assessed.
        period_start: Start of the audit period.
        period_end: End of the audit period.
        check_results: Results from automated compliance checks.
        collected_evidence: Inventory of collected evidence.

    Returns:
        Complete SOC 2 evidence package.
    """
    # Create management assertion
    assertion = ManagementAssertion(
        organization_name=organization_name,
        system_name=system_name,
        period_start=period_start,
        period_end=period_end,
        categories_in_scope=["Security"],  # Default to Security only
        description_criteria=(
            "The description fairly presents the system that was designed "
            "and implemented throughout the assessment period."
        ),
        control_design=(
            "The controls stated in the description were suitably designed "
            "to provide reasonable assurance that service commitments and "
            "system requirements would be achieved."
        ),
        control_effectiveness=(
            "The controls stated in the description operated effectively "
            "throughout the assessment period."
        ),
    )

    # Create system description
    description = SystemDescription(
        organization_name=organization_name,
        system_name=system_name,
        services_provided="Cloud-based services as described in service agreements.",
        principal_service_commitments=[
            "Maintain the security of user data",
            "Maintain system availability per SLA",
            "Process data accurately and completely",
        ],
        system_requirements=[
            "Implement and maintain security controls",
            "Monitor and respond to security events",
            "Maintain backup and recovery capabilities",
        ],
        trust_services_categories=["Security"],
    )

    # Create test results summary
    test_results = TestResultsSummary(
        period_start=period_start,
        period_end=period_end,
    )

    # Convert check results to control test results
    if check_results:
        control_results: dict[str, ControlTestResult] = {}

        for check in check_results:
            control_id = check.get("control_id", "")
            if not control_id:
                continue

            if control_id not in control_results:
                control_results[control_id] = ControlTestResult(
                    control_id=control_id,
                    control_title=check.get("control_title", ""),
                    test_procedures=["Automated compliance check execution"],
                )

            result = control_results[control_id]
            result.sample_size += 1

            if not check.get("passed", True):
                result.exceptions_count += 1
                result.evidence_references.append(check.get("check_id", ""))

        # Determine test result status
        for result in control_results.values():
            if result.exceptions_count == 0:
                result.test_result = TestResult.OPERATING_EFFECTIVELY
            elif result.exceptions_count < result.sample_size:
                result.test_result = TestResult.EXCEPTION_NOTED
            else:
                result.test_result = TestResult.DEVIATION_NOTED

        test_results.test_results = list(control_results.values())
        test_results.calculate_statistics()

    # Build the package
    package = SOC2EvidencePackage(
        organization_name=organization_name,
        system_name=system_name,
        period_start=period_start,
        period_end=period_end,
        management_assertion=assertion,
        system_description=description,
        test_results=test_results,
        control_matrix=generate_control_matrix(),
        automated_check_results=check_results or [],
        evidence_inventory=collected_evidence or [],
    )

    logger.info(
        f"Generated SOC 2 evidence package for {organization_name} "
        f"({period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')})"
    )

    return package


def export_evidence_package(
    package: SOC2EvidencePackage,
    output_dir: Path | str,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """
    Export evidence package to files.

    Args:
        package: The evidence package to export.
        output_dir: Directory to write output files.
        formats: List of formats to export (json, markdown).

    Returns:
        Dictionary mapping format names to output file paths.
    """
    if formats is None:
        formats = ["json", "markdown"]

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs: dict[str, Path] = {}

    if "json" in formats:
        json_path = output_dir / f"soc2_evidence_package_{package.package_id[:8]}.json"
        json_path.write_text(
            json.dumps(package.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        outputs["json"] = json_path
        logger.info(f"Exported JSON evidence package to {json_path}")

    if "markdown" in formats:
        md_path = output_dir / f"soc2_evidence_package_{package.package_id[:8]}.md"
        md_content = _generate_markdown_report(package)
        md_path.write_text(md_content, encoding="utf-8")
        outputs["markdown"] = md_path
        logger.info(f"Exported Markdown evidence package to {md_path}")

    return outputs


def _generate_markdown_report(package: SOC2EvidencePackage) -> str:
    """Generate a Markdown report from an evidence package."""
    lines = [
        f"# SOC 2 Type II Evidence Package",
        f"",
        f"**Organization:** {package.organization_name}",
        f"**System:** {package.system_name}",
        f"**Period:** {package.period_start.strftime('%B %d, %Y')} to {package.period_end.strftime('%B %d, %Y')}",
        f"**Generated:** {package.generated_at.strftime('%B %d, %Y at %H:%M UTC')}",
        f"**Package ID:** {package.package_id}",
        f"",
        "---",
        "",
    ]

    # Management Assertion
    if package.management_assertion:
        lines.extend([
            "## Management Assertion",
            "",
            package.management_assertion.generate_text(),
            "",
            "---",
            "",
        ])

    # Test Results Summary
    if package.test_results:
        summary = package.test_results.to_dict()["summary"]
        lines.extend([
            "## Testing Results Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Controls Tested | {summary['total_controls']} |",
            f"| Controls Operating Effectively | {summary['effective_controls']} |",
            f"| Exceptions Noted | {summary['exceptions_noted']} |",
            f"| Deviations Noted | {summary['deviations_noted']} |",
            f"| Effectiveness Rate | {summary['effectiveness_rate']}% |",
            "",
            "---",
            "",
        ])

    # Control Matrix (abbreviated)
    if package.control_matrix:
        lines.extend([
            "## Control Matrix",
            "",
            "| Control ID | Title | Status | Evidence Sources |",
            "|------------|-------|--------|------------------|",
        ])
        for entry in package.control_matrix[:20]:  # First 20 entries
            evidence_types = ", ".join(
                s.get("type", "") for s in entry.get("evidence_sources", [])[:3]
            )
            lines.append(
                f"| {entry['control_id']} | {entry['control_title'][:40]}... | "
                f"{entry['automation_status']} | {evidence_types or 'Automated'} |"
            )
        if len(package.control_matrix) > 20:
            lines.append(f"| ... | ({len(package.control_matrix) - 20} more controls) | ... | ... |")
        lines.extend(["", "---", ""])

    # Evidence Summary
    lines.extend([
        "## Evidence Summary",
        "",
        f"- **Automated Check Results:** {len(package.automated_check_results)} checks executed",
        f"- **Evidence Items Collected:** {len(package.evidence_inventory)} items",
        "",
    ])

    return "\n".join(lines)


def get_report_statistics() -> dict[str, Any]:
    """
    Get statistics about SOC 2 reporting capabilities.

    Returns:
        Dictionary with report statistics.
    """
    control_matrix = generate_control_matrix()
    manual_stats = get_manual_control_statistics()

    automated_count = sum(
        1 for c in control_matrix if c.get("automation_status") == "automated"
    )
    partial_count = sum(
        1 for c in control_matrix if c.get("automation_status") == "partial"
    )
    manual_count = sum(
        1 for c in control_matrix if c.get("automation_status") == "manual"
    )

    return {
        "total_controls": len(control_matrix),
        "automated_controls": automated_count,
        "partially_automated_controls": partial_count,
        "manual_controls": manual_count,
        "evidence_types_supported": manual_stats["unique_evidence_types"],
        "platforms_supported": manual_stats["unique_platforms"],
        "report_components": [
            "Management Assertion",
            "System Description",
            "Control Matrix",
            "Testing Results Summary",
            "Evidence Package",
        ],
        "export_formats": ["JSON", "Markdown"],
    }


__all__ = [
    # Enums
    "TestResult",
    "ControlStatus",
    # Data classes
    "ControlTestResult",
    "ManagementAssertion",
    "SystemDescription",
    "TestResultsSummary",
    "SOC2EvidencePackage",
    # Functions
    "generate_control_matrix",
    "generate_testing_procedures",
    "generate_evidence_package",
    "export_evidence_package",
    "get_report_statistics",
]
