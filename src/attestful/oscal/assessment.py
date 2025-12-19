"""
OSCAL Assessment Results generator.

Provides functionality for generating OSCAL Assessment Results documents
from compliance scan results and evidence collection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import orjson
import yaml

from attestful.core.exceptions import OSCALError
from attestful.core.logging import get_logger
from attestful.core.models import (
    CheckResult,
    CheckStatus,
    Evidence,
    MaturityLevel,
    MaturityScore,
)
from attestful.oscal.models import (
    AssessmentResults,
    BackMatter,
    Finding,
    FindingTarget,
    ImportAP,
    ImportSSP,
    LocalDefinitions,
    Metadata,
    Milestone,
    Observation,
    Origin,
    Party,
    PlanOfActionAndMilestones,
    PoamItem,
    PoamLocalDefinitions,
    Property,
    RelevantEvidence,
    Response,
    ResponsibleParty,
    Result,
    Risk,
    Role,
    Subject,
    SystemId,
)

logger = get_logger("oscal.assessment")


@dataclass
class AssessmentConfig:
    """Configuration for assessment results generation."""

    # Required fields
    title: str
    description: str = "Automated compliance assessment"

    # Assessment plan reference
    assessment_plan_href: str = "#assessment-plan"

    # Organization info
    organization_name: str = "Organization"
    organization_uuid: UUID = field(default_factory=uuid4)
    assessor_name: str = "Automated Scanner"
    assessor_uuid: UUID = field(default_factory=uuid4)

    # Version
    version: str = "1.0.0"


class AssessmentResultsGenerator:
    """
    Generate OSCAL Assessment Results documents.

    Converts compliance check results and evidence into OSCAL format.
    """

    def __init__(
        self,
        config: AssessmentConfig,
    ) -> None:
        """
        Initialize the assessment results generator.

        Args:
            config: Configuration for the assessment
        """
        self.config = config
        self.check_results: list[CheckResult] = []
        self.evidence_items: list[Evidence] = []
        self.start_time: datetime = datetime.now(timezone.utc)
        self.end_time: datetime | None = None

    def add_check_results(self, results: list[CheckResult]) -> None:
        """Add compliance check results."""
        self.check_results.extend(results)
        logger.debug(f"Added {len(results)} check results")

    def add_evidence(self, evidence: list[Evidence]) -> None:
        """Add evidence items."""
        self.evidence_items.extend(evidence)
        logger.debug(f"Added {len(evidence)} evidence items")

    def set_assessment_period(
        self,
        start: datetime,
        end: datetime | None = None,
    ) -> None:
        """Set the assessment period."""
        self.start_time = start
        self.end_time = end or datetime.now(timezone.utc)

    def generate(self) -> AssessmentResults:
        """
        Generate the OSCAL Assessment Results document.

        Returns:
            Complete AssessmentResults document
        """
        logger.info(f"Generating Assessment Results: {self.config.title}")

        if self.end_time is None:
            self.end_time = datetime.now(timezone.utc)

        # Build metadata
        metadata = self._build_metadata()

        # Build import-ap
        import_ap = ImportAP(href=self.config.assessment_plan_href)

        # Build local definitions (for assessor info)
        local_definitions = self._build_local_definitions()

        # Build result
        result = self._build_result()

        # Create the assessment results
        assessment_results = AssessmentResults(
            metadata=metadata,
            import_ap=import_ap,
            local_definitions=local_definitions,
            results=[result],
        )

        logger.info(
            f"Generated Assessment Results with {len(self.check_results)} checks, "
            f"{len(self.evidence_items)} evidence items"
        )

        return assessment_results

    def _build_metadata(self) -> Metadata:
        """Build the assessment results metadata section."""
        now = datetime.now(timezone.utc)

        # Build roles
        roles = [
            Role(
                id="assessor",
                title="Assessor",
                description="Individual or tool performing the assessment",
            ),
            Role(
                id="assessment-lead",
                title="Assessment Lead",
                description="Person responsible for the assessment",
            ),
        ]

        # Build parties
        parties = [
            Party(
                uuid=self.config.organization_uuid,
                type="organization",
                name=self.config.organization_name,
            ),
            Party(
                uuid=self.config.assessor_uuid,
                type="organization",
                name=self.config.assessor_name,
            ),
        ]

        # Responsible parties
        responsible_parties = [
            ResponsibleParty(
                role_id="assessor",
                party_uuids=[self.config.assessor_uuid],
            ),
        ]

        return Metadata(
            title=self.config.title,
            last_modified=now,
            version=self.config.version,
            oscal_version="1.1.2",
            roles=roles,
            parties=parties,
            responsible_parties=responsible_parties,
            props=[
                Property(name="assessment-type", value="automated"),
            ],
        )

    def _build_local_definitions(self) -> LocalDefinitions:
        """Build local definitions section."""
        return LocalDefinitions(
            assessment_assets={
                "assessment-platforms": [
                    {
                        "uuid": str(uuid4()),
                        "title": "Attestful Scanner",
                        "props": [
                            {"name": "type", "value": "automated"},
                        ],
                        "uses-components": [],
                    }
                ]
            }
        )

    def _build_result(self) -> Result:
        """Build the result section."""
        # Build observations from check results
        observations = self._build_observations()

        # Build findings from check results
        findings = self._build_findings()

        # Build reviewed controls summary
        reviewed_controls = self._build_reviewed_controls()

        return Result(
            uuid=uuid4(),
            title=f"Assessment Result - {self.start_time.strftime('%Y-%m-%d')}",
            description=self.config.description,
            start=self.start_time,
            end=self.end_time,
            observations=observations if observations else None,
            findings=findings if findings else None,
            reviewed_controls=reviewed_controls,
            props=[
                Property(
                    name="total-checks",
                    value=str(len(self.check_results)),
                ),
                Property(
                    name="passed-checks",
                    value=str(sum(1 for r in self.check_results if r.passed)),
                ),
                Property(
                    name="failed-checks",
                    value=str(sum(1 for r in self.check_results if not r.passed)),
                ),
            ],
        )

    def _build_observations(self) -> list[Observation]:
        """Build observations from check results and evidence."""
        observations: list[Observation] = []

        # Create observations from check results
        for result in self.check_results:
            obs = Observation(
                uuid=uuid4(),
                title=f"Check: {result.check.title if result.check else result.check_id}",
                description=self._get_observation_description(result),
                methods=["AUTOMATED"],
                types=["finding"],
                collected=result.evaluated_at,
                props=[
                    Property(name="check-id", value=result.check_id or (result.check.id if result.check else "")),
                    Property(name="resource-id", value=result.resource_id),
                    Property(name="status", value="pass" if result.passed else "fail"),
                    Property(name="severity", value=result.severity.value if hasattr(result.severity, 'value') else str(result.severity)),
                ],
                subjects=[
                    Subject(
                        subject_uuid=uuid4(),
                        type="resource",
                        title=result.resource_id,
                    )
                ] if result.resource_id else None,
            )
            observations.append(obs)

        # Create observations from evidence
        for evidence in self.evidence_items:
            obs = Observation(
                uuid=uuid4(),
                title=f"Evidence: {evidence.evidence_type}",
                description=f"Evidence collected from {evidence.platform}",
                methods=["AUTOMATED"],
                types=["evidence"],
                collected=evidence.collected_at,
                props=[
                    Property(name="platform", value=evidence.platform),
                    Property(name="evidence-type", value=evidence.evidence_type),
                ],
                relevant_evidence=[
                    RelevantEvidence(
                        href=f"#evidence-{evidence.id}",
                        description=f"Evidence data from {evidence.platform}",
                    )
                ] if evidence.id else None,
            )
            observations.append(obs)

        return observations

    def _build_findings(self) -> list[Finding]:
        """Build findings from failed check results."""
        findings: list[Finding] = []

        # Only create findings for failed checks
        failed_checks = [r for r in self.check_results if not r.passed]

        for result in failed_checks:
            check_id = result.check_id or (result.check.id if result.check else "unknown")
            check_title = result.check.title if result.check else check_id

            finding = Finding(
                uuid=uuid4(),
                title=f"Finding: {check_title}",
                description=self._get_finding_description(result),
                target=FindingTarget(
                    type="objective-id",
                    target_id=check_id,
                    status={"state": "not-satisfied"},
                ),
                props=[
                    Property(name="severity", value=result.severity.value if hasattr(result.severity, 'value') else str(result.severity)),
                    Property(name="resource-id", value=result.resource_id),
                    Property(name="resource-type", value=result.resource_type or "unknown"),
                ],
            )
            findings.append(finding)

        return findings

    def _build_reviewed_controls(self) -> dict[str, Any]:
        """Build the reviewed controls summary."""
        # Collect unique control IDs from check results
        control_ids: set[str] = set()
        for result in self.check_results:
            if result.check and result.check.framework_mappings:
                for controls in result.check.framework_mappings.values():
                    control_ids.update(controls)
            elif result.check_id:
                control_ids.add(result.check_id)

        return {
            "control-selections": [
                {
                    "description": "Controls reviewed during this assessment",
                    "include-controls": [
                        {"control-id": cid} for cid in sorted(control_ids)
                    ] if control_ids else [],
                }
            ]
        }

    def _get_observation_description(self, result: CheckResult) -> str:
        """Get description for an observation."""
        check_title = result.check.title if result.check else result.check_id
        status = "passed" if result.passed else "failed"

        desc = f"Automated check '{check_title}' {status}"
        if result.resource_id:
            desc += f" for resource '{result.resource_id}'"
        if result.message:
            desc += f". {result.message}"

        return desc

    def _get_finding_description(self, result: CheckResult) -> str:
        """Get description for a finding."""
        check_title = result.check.title if result.check else result.check_id
        desc = f"Check '{check_title}' failed"

        if result.resource_id:
            desc += f" for resource '{result.resource_id}'"

        if result.message:
            desc += f". Details: {result.message}"

        if result.check and result.check.remediation:
            desc += f" Remediation: {result.check.remediation}"

        return desc

    def save(self, path: str | Path, format: str = "json") -> Path:
        """
        Generate and save the assessment results to a file.

        Args:
            path: Output file path
            format: Output format ("json" or "yaml")

        Returns:
            Path to the saved file
        """
        path = Path(path)
        results = self.generate()

        # Wrap in standard OSCAL format
        if format == "json":
            content = '{"assessment-results": ' + results.to_json() + "}"
            if not path.suffix:
                path = path.with_suffix(".json")
        elif format == "yaml":
            data = {"assessment-results": results.model_dump(by_alias=True, exclude_none=True, mode="json")}
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)
            if not path.suffix:
                path = path.with_suffix(".yaml")
        else:
            raise OSCALError(f"Unsupported format: {format}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        logger.info(f"Saved Assessment Results to {path}")
        return path


class AssessmentResultsLoader:
    """Load and parse existing OSCAL Assessment Results documents."""

    def __init__(self) -> None:
        self._cache: dict[str, AssessmentResults] = {}

    def load(
        self, path: str | Path, *, use_cache: bool = True
    ) -> AssessmentResults:
        """
        Load assessment results from a file.

        Args:
            path: Path to the assessment results file
            use_cache: Whether to use cached results if available

        Returns:
            Parsed AssessmentResults

        Raises:
            OSCALError: If the file cannot be loaded
        """
        path = Path(path)
        cache_key = str(path.resolve())

        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        if not path.exists():
            raise OSCALError(f"Assessment results file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
            suffix = path.suffix.lower()

            if suffix == ".json":
                data = orjson.loads(content)
            elif suffix in (".yaml", ".yml"):
                data = yaml.safe_load(content)
            else:
                # Try JSON first
                try:
                    data = orjson.loads(content)
                except orjson.JSONDecodeError:
                    data = yaml.safe_load(content)

            # Handle wrapped format
            if "assessment-results" in data:
                data = data["assessment-results"]

            results = AssessmentResults.model_validate(data)

            if use_cache:
                self._cache[cache_key] = results

            logger.info(f"Loaded Assessment Results: {results.metadata.title}")
            return results

        except Exception as e:
            raise OSCALError(f"Failed to load assessment results: {e}") from e

    def clear_cache(self) -> None:
        """Clear the cache."""
        self._cache.clear()


def create_assessment_from_scan(
    title: str,
    check_results: list[CheckResult],
    evidence: list[Evidence] | None = None,
    **kwargs: Any,
) -> AssessmentResults:
    """
    Convenience function to create assessment results from scan results.

    Args:
        title: Assessment title
        check_results: Results from compliance scans
        evidence: Optional evidence items
        **kwargs: Additional AssessmentConfig parameters

    Returns:
        Generated AssessmentResults
    """
    config = AssessmentConfig(title=title, **kwargs)
    generator = AssessmentResultsGenerator(config)
    generator.add_check_results(check_results)

    if evidence:
        generator.add_evidence(evidence)

    return generator.generate()


def get_assessment_summary(results: AssessmentResults) -> dict[str, Any]:
    """
    Get a summary of assessment results.

    Args:
        results: The assessment results document

    Returns:
        Dictionary with summary statistics
    """
    if not results.results:
        return {
            "total_findings": 0,
            "total_observations": 0,
            "status": "no-results",
        }

    result = results.results[0]  # Use first result

    total_findings = len(result.findings) if result.findings else 0
    total_observations = len(result.observations) if result.observations else 0

    # Extract pass/fail counts from properties
    passed = 0
    failed = 0
    if result.props:
        for prop in result.props:
            if prop.name == "passed-checks":
                passed = int(prop.value)
            elif prop.name == "failed-checks":
                failed = int(prop.value)

    return {
        "title": results.metadata.title,
        "assessment_date": result.start.isoformat() if result.start else None,
        "total_findings": total_findings,
        "total_observations": total_observations,
        "passed_checks": passed,
        "failed_checks": failed,
        "pass_rate": (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0,
        "status": "complete" if result.end else "in-progress",
    }


@dataclass
class ScanResultMappingConfig:
    """Configuration for mapping scan results to OSCAL."""

    # Include passed checks as observations
    include_passed: bool = True
    # Include evidence references in findings
    include_evidence: bool = True
    # Map severity to OSCAL risk levels
    map_severity_to_risk: bool = True
    # Group findings by control
    group_by_control: bool = False


class ScanResultMapper:
    """
    Map scan results to OSCAL Assessment Results format.

    Converts compliance check results into OSCAL-compliant observations
    and findings with proper risk level mappings.
    """

    # Mapping from Attestful severity to OSCAL risk levels
    SEVERITY_TO_RISK: dict[str, str] = {
        "critical": "very-high",
        "high": "high",
        "medium": "moderate",
        "low": "low",
        "info": "very-low",
    }

    # Mapping from Attestful severity to OSCAL state
    SEVERITY_TO_STATE: dict[str, str] = {
        "critical": "not-satisfied",
        "high": "not-satisfied",
        "medium": "not-satisfied",
        "low": "not-satisfied",
        "info": "other",
    }

    def __init__(self, config: ScanResultMappingConfig | None = None) -> None:
        """
        Initialize the scan result mapper.

        Args:
            config: Optional mapping configuration
        """
        self.config = config or ScanResultMappingConfig()

    def map_results(
        self,
        check_results: list[CheckResult],
        scan_id: str | None = None,
        scan_time: datetime | None = None,
    ) -> tuple[list[Observation], list[Finding]]:
        """
        Map scan results to OSCAL observations and findings.

        Args:
            check_results: List of check results from compliance scans
            scan_id: Optional scan identifier
            scan_time: Optional scan timestamp

        Returns:
            Tuple of (observations, findings)
        """
        observations: list[Observation] = []
        findings: list[Finding] = []

        scan_time = scan_time or datetime.now(timezone.utc)
        scan_id = scan_id or str(uuid4())

        for result in check_results:
            # Create observation for each resource checked
            obs = self._create_observation(result, scan_id, scan_time)
            observations.append(obs)

            # Create finding for failed checks
            if not result.passed:
                finding = self._create_finding(result, obs.uuid, scan_id)
                findings.append(finding)

        logger.info(
            f"Mapped {len(check_results)} scan results to "
            f"{len(observations)} observations and {len(findings)} findings"
        )

        return observations, findings

    def _create_observation(
        self,
        result: CheckResult,
        scan_id: str,
        scan_time: datetime,
    ) -> Observation:
        """Create an OSCAL observation from a check result."""
        check_id = result.check_id or (result.check.id if result.check else "unknown")
        check_title = result.check.title if result.check else check_id

        # Build properties
        props = [
            Property(name="check-id", value=check_id),
            Property(name="scan-id", value=scan_id),
            Property(name="status", value="pass" if result.passed else "fail"),
        ]

        # Add resource information
        if result.resource_id:
            props.append(Property(name="resource-id", value=result.resource_id))
        if result.resource_type:
            props.append(Property(name="resource-type", value=result.resource_type))

        # Add severity as risk level
        severity_str = (
            result.severity.value
            if hasattr(result.severity, "value")
            else str(result.severity)
        )
        if self.config.map_severity_to_risk:
            risk_level = self.SEVERITY_TO_RISK.get(severity_str.lower(), "moderate")
            props.append(Property(name="risk-level", value=risk_level))
        props.append(Property(name="severity", value=severity_str))

        # Build subjects (resources checked)
        subjects = None
        if result.resource_id:
            subjects = [
                Subject(
                    subject_uuid=uuid4(),
                    type="inventory-item" if result.resource_type else "resource",
                    title=result.resource_id,
                    props=[
                        Property(name="resource-type", value=result.resource_type)
                    ] if result.resource_type else None,
                )
            ]

        # Build relevant evidence if configured
        relevant_evidence = None
        if self.config.include_evidence and result.evidence:
            relevant_evidence = [
                RelevantEvidence(
                    href=f"#evidence-{result.id}",
                    description=f"Evidence data for check {check_id}",
                )
            ]

        # Build origin information
        origins = [
            Origin(
                actors=[
                    {
                        "type": "tool",
                        "actor-uuid": str(uuid4()),
                        "props": [
                            {"name": "tool-name", "value": "Attestful Scanner"},
                        ],
                    }
                ],
            )
        ]

        return Observation(
            uuid=uuid4(),
            title=f"Check: {check_title}",
            description=self._format_observation_description(result),
            methods=["AUTOMATED"],
            types=["finding" if not result.passed else "check"],
            collected=result.evaluated_at or scan_time,
            props=props,
            subjects=subjects,
            relevant_evidence=relevant_evidence,
            origins=origins,
        )

    def _create_finding(
        self,
        result: CheckResult,
        observation_uuid: UUID,
        scan_id: str,
    ) -> Finding:
        """Create an OSCAL finding from a failed check result."""
        check_id = result.check_id or (result.check.id if result.check else "unknown")
        check_title = result.check.title if result.check else check_id

        # Determine severity and state
        severity_str = (
            result.severity.value
            if hasattr(result.severity, "value")
            else str(result.severity)
        )
        risk_level = self.SEVERITY_TO_RISK.get(severity_str.lower(), "moderate")
        state = self.SEVERITY_TO_STATE.get(severity_str.lower(), "not-satisfied")

        # Build properties
        props = [
            Property(name="check-id", value=check_id),
            Property(name="scan-id", value=scan_id),
            Property(name="severity", value=severity_str),
            Property(name="risk-level", value=risk_level),
        ]

        if result.resource_id:
            props.append(Property(name="resource-id", value=result.resource_id))
        if result.resource_type:
            props.append(Property(name="resource-type", value=result.resource_type))

        # Add control mappings if available
        if result.check and result.check.framework_mappings:
            for framework, controls in result.check.framework_mappings.items():
                for control in controls:
                    props.append(
                        Property(
                            name="related-control",
                            value=control,
                            ns=f"https://attestful.dev/ns/{framework}",
                        )
                    )

        # Build target (what control/objective is affected)
        target = FindingTarget(
            type="objective-id",
            target_id=check_id,
            status={"state": state},
            props=[
                Property(name="risk", value=risk_level),
            ],
        )

        # Build related observations list
        related_observations = [{"observation-uuid": str(observation_uuid)}]

        return Finding(
            uuid=uuid4(),
            title=f"Finding: {check_title}",
            description=self._format_finding_description(result),
            target=target,
            props=props,
            related_observations=related_observations,
        )

    def _format_observation_description(self, result: CheckResult) -> str:
        """Format observation description."""
        check_title = result.check.title if result.check else result.check_id
        status = "passed" if result.passed else "failed"

        desc = f"Automated compliance check '{check_title}' {status}"
        if result.resource_id:
            desc += f" for resource '{result.resource_id}'"
        if result.resource_type:
            desc += f" (type: {result.resource_type})"
        if result.message:
            desc += f". Result: {result.message}"

        return desc

    def _format_finding_description(self, result: CheckResult) -> str:
        """Format finding description for failed checks."""
        check_title = result.check.title if result.check else result.check_id

        desc = f"Compliance check '{check_title}' failed"
        if result.resource_id:
            desc += f" for resource '{result.resource_id}'"

        if result.message:
            desc += f". Issue: {result.message}"

        if result.check:
            if result.check.description:
                desc += f" Check description: {result.check.description}"
            if result.check.remediation:
                desc += f" Recommended remediation: {result.check.remediation}"

        return desc

    def map_severity_to_risk_level(self, severity: str) -> str:
        """
        Map a severity string to OSCAL risk level.

        Args:
            severity: Severity string (critical, high, medium, low, info)

        Returns:
            OSCAL risk level (very-high, high, moderate, low, very-low)
        """
        return self.SEVERITY_TO_RISK.get(severity.lower(), "moderate")

    def get_findings_by_control(
        self,
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """
        Group findings by control ID.

        Args:
            findings: List of OSCAL findings

        Returns:
            Dictionary mapping control IDs to findings
        """
        by_control: dict[str, list[Finding]] = {}

        for finding in findings:
            control_id = finding.target.target_id if finding.target else "unknown"
            if control_id not in by_control:
                by_control[control_id] = []
            by_control[control_id].append(finding)

        return by_control

    def get_findings_by_severity(
        self,
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """
        Group findings by severity/risk level.

        Args:
            findings: List of OSCAL findings

        Returns:
            Dictionary mapping risk levels to findings
        """
        by_severity: dict[str, list[Finding]] = {
            "very-high": [],
            "high": [],
            "moderate": [],
            "low": [],
            "very-low": [],
        }

        for finding in findings:
            risk_level = "moderate"  # default
            if finding.props:
                for prop in finding.props:
                    if prop.name == "risk-level":
                        risk_level = prop.value
                        break

            if risk_level in by_severity:
                by_severity[risk_level].append(finding)

        return by_severity

    def get_summary(
        self,
        observations: list[Observation],
        findings: list[Finding],
    ) -> dict[str, Any]:
        """
        Get summary statistics from mapped results.

        Args:
            observations: List of OSCAL observations
            findings: List of OSCAL findings

        Returns:
            Summary dictionary
        """
        by_severity = self.get_findings_by_severity(findings)

        total_checks = len(observations)
        total_findings = len(findings)
        passed_checks = total_checks - total_findings

        return {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": total_findings,
            "pass_rate": (passed_checks / total_checks * 100) if total_checks > 0 else 0,
            "findings_by_severity": {
                level: len(items) for level, items in by_severity.items()
            },
            "critical_findings": len(by_severity["very-high"]),
            "high_findings": len(by_severity["high"]),
            "medium_findings": len(by_severity["moderate"]),
            "low_findings": len(by_severity["low"]),
        }


@dataclass
class MaturityScoreMappingConfig:
    """Configuration for mapping maturity scores to OSCAL."""

    # Minimum level to consider as "satisfied"
    satisfied_threshold: int = 2
    # Include trend data in observations
    include_trends: bool = True
    # Include evidence in observations
    include_evidence: bool = True
    # Framework identifier (e.g., "nist-csf-2.0")
    framework: str = "nist-csf-2.0"


@dataclass
class TrendData:
    """Trend data for maturity scores."""

    previous_score: float | None = None
    previous_level: int | None = None
    change_direction: str = "stable"  # "improving", "declining", "stable"
    change_amount: float = 0.0


class MaturityScoreMapper:
    """
    Map maturity scores to OSCAL Assessment Results format.

    Converts maturity assessment data into OSCAL-compliant observations
    and findings with implementation status mappings.
    """

    # Mapping from maturity levels to OSCAL implementation status
    LEVEL_TO_IMPLEMENTATION_STATUS: dict[int, str] = {
        0: "not-implemented",
        1: "partial",
        2: "planned",
        3: "implemented",
        4: "implemented",
    }

    # Mapping from maturity levels to OSCAL satisfaction state
    LEVEL_TO_STATE: dict[int, str] = {
        0: "not-satisfied",
        1: "not-satisfied",
        2: "partially-satisfied",
        3: "satisfied",
        4: "satisfied",
    }

    # Risk level based on maturity level
    LEVEL_TO_RISK: dict[int, str] = {
        0: "very-high",
        1: "high",
        2: "moderate",
        3: "low",
        4: "very-low",
    }

    def __init__(self, config: MaturityScoreMappingConfig | None = None) -> None:
        """
        Initialize the maturity score mapper.

        Args:
            config: Optional mapping configuration
        """
        self.config = config or MaturityScoreMappingConfig()

    def map_scores(
        self,
        maturity_scores: list[MaturityScore],
        evidence_items: list[Evidence] | None = None,
        trends: dict[str, TrendData] | None = None,
        assessment_id: str | None = None,
        assessment_time: datetime | None = None,
    ) -> tuple[list[Observation], list[Finding]]:
        """
        Map maturity scores to OSCAL observations and findings.

        Args:
            maturity_scores: List of maturity scores from assessment
            evidence_items: Optional list of evidence items supporting the scores
            trends: Optional trend data for each entity (keyed by entity_id)
            assessment_id: Optional assessment identifier
            assessment_time: Optional assessment timestamp

        Returns:
            Tuple of (observations, findings)
        """
        observations: list[Observation] = []
        findings: list[Finding] = []

        assessment_time = assessment_time or datetime.now(timezone.utc)
        assessment_id = assessment_id or str(uuid4())

        # Index evidence by control
        evidence_by_control: dict[str, list[Evidence]] = {}
        if evidence_items:
            for ev in evidence_items:
                for control_id in ev.control_mappings if hasattr(ev, "control_mappings") and ev.control_mappings else []:
                    if control_id not in evidence_by_control:
                        evidence_by_control[control_id] = []
                    evidence_by_control[control_id].append(ev)

        for score in maturity_scores:
            # Get trend data if available
            trend = trends.get(score.entity_id) if trends else None

            # Create observation for each maturity score
            related_evidence = evidence_by_control.get(score.entity_id, [])
            obs = self._create_observation(
                score, related_evidence, trend, assessment_id, assessment_time
            )
            observations.append(obs)

            # Create finding for low maturity or missing evidence
            level = score.level.value if isinstance(score.level, MaturityLevel) else int(score.level)
            if level < self.config.satisfied_threshold or score.missing_evidence_types:
                finding = self._create_finding(score, obs.uuid, assessment_id)
                findings.append(finding)

        logger.info(
            f"Mapped {len(maturity_scores)} maturity scores to "
            f"{len(observations)} observations and {len(findings)} findings"
        )

        return observations, findings

    def _create_observation(
        self,
        score: MaturityScore,
        evidence: list[Evidence],
        trend: TrendData | None,
        assessment_id: str,
        assessment_time: datetime,
    ) -> Observation:
        """Create an OSCAL observation from a maturity score."""
        level = score.level.value if isinstance(score.level, MaturityLevel) else int(score.level)
        impl_status = self.LEVEL_TO_IMPLEMENTATION_STATUS.get(level, "partial")

        # Build properties
        props = [
            Property(name="entity-id", value=score.entity_id),
            Property(name="entity-type", value=score.entity_type),
            Property(name="assessment-id", value=assessment_id),
            Property(name="maturity-level", value=str(level)),
            Property(name="maturity-score", value=f"{score.score:.2f}"),
            Property(name="implementation-status", value=impl_status),
            Property(name="evidence-count", value=str(score.evidence_count)),
            Property(name="confidence", value=f"{score.confidence:.2f}"),
            Property(
                name="framework",
                value=self.config.framework,
                ns="https://attestful.dev/ns/frameworks",
            ),
        ]

        # Add risk level
        risk_level = self.LEVEL_TO_RISK.get(level, "moderate")
        props.append(Property(name="risk-level", value=risk_level))

        # Add trend data if available and configured
        if self.config.include_trends and trend:
            props.extend([
                Property(name="trend-direction", value=trend.change_direction),
                Property(name="trend-change", value=f"{trend.change_amount:.2f}"),
            ])
            if trend.previous_level is not None:
                props.append(
                    Property(name="previous-level", value=str(trend.previous_level))
                )

        # Add missing evidence types
        if score.missing_evidence_types:
            for i, ev_type in enumerate(score.missing_evidence_types):
                props.append(
                    Property(
                        name=f"missing-evidence-{i + 1}",
                        value=ev_type,
                        ns="https://attestful.dev/ns/evidence",
                    )
                )

        # Build relevant evidence references
        relevant_evidence = None
        if self.config.include_evidence and evidence:
            relevant_evidence = [
                RelevantEvidence(
                    href=f"#evidence-{ev.id if hasattr(ev, 'id') else uuid4()}",
                    description=f"Evidence: {ev.evidence_type} from {ev.platform}",
                )
                for ev in evidence[:10]  # Limit to 10 evidence references
            ]

        # Build origin information
        origins = [
            Origin(
                actors=[
                    {
                        "type": "tool",
                        "actor-uuid": str(uuid4()),
                        "props": [
                            {"name": "tool-name", "value": "Attestful Maturity Analyzer"},
                        ],
                    }
                ],
            )
        ]

        return Observation(
            uuid=uuid4(),
            title=f"Maturity Assessment: {score.entity_id}",
            description=self._format_observation_description(score, trend),
            methods=["EXAMINE", "INTERVIEW"],
            types=["maturity-assessment"],
            collected=score.calculated_at or assessment_time,
            props=props,
            relevant_evidence=relevant_evidence,
            origins=origins,
        )

    def _create_finding(
        self,
        score: MaturityScore,
        observation_uuid: UUID,
        assessment_id: str,
    ) -> Finding:
        """Create an OSCAL finding from a low maturity score or missing evidence."""
        level = score.level.value if isinstance(score.level, MaturityLevel) else int(score.level)
        state = self.LEVEL_TO_STATE.get(level, "not-satisfied")
        risk_level = self.LEVEL_TO_RISK.get(level, "moderate")

        # Build properties
        props = [
            Property(name="entity-id", value=score.entity_id),
            Property(name="entity-type", value=score.entity_type),
            Property(name="assessment-id", value=assessment_id),
            Property(name="maturity-level", value=str(level)),
            Property(name="target-level", value=str(self.config.satisfied_threshold)),
            Property(name="risk-level", value=risk_level),
            Property(
                name="framework",
                value=self.config.framework,
                ns="https://attestful.dev/ns/frameworks",
            ),
        ]

        # Add gap information
        gap = self.config.satisfied_threshold - level
        if gap > 0:
            props.append(Property(name="maturity-gap", value=str(gap)))

        # Add missing evidence
        if score.missing_evidence_types:
            props.append(
                Property(
                    name="missing-evidence-count",
                    value=str(len(score.missing_evidence_types)),
                )
            )
            for i, ev_type in enumerate(score.missing_evidence_types[:5]):  # Limit
                props.append(
                    Property(
                        name=f"missing-evidence-{i + 1}",
                        value=ev_type,
                        ns="https://attestful.dev/ns/evidence",
                    )
                )

        # Build target
        target = FindingTarget(
            type="objective-id",
            target_id=score.entity_id,
            status={"state": state},
            props=[
                Property(name="risk", value=risk_level),
                Property(name="implementation-status", value=self.LEVEL_TO_IMPLEMENTATION_STATUS.get(level, "partial")),
            ],
        )

        # Build related observations list
        related_observations = [{"observation-uuid": str(observation_uuid)}]

        return Finding(
            uuid=uuid4(),
            title=f"Maturity Gap: {score.entity_id}",
            description=self._format_finding_description(score),
            target=target,
            props=props,
            related_observations=related_observations,
        )

    def _format_observation_description(
        self,
        score: MaturityScore,
        trend: TrendData | None,
    ) -> str:
        """Format observation description."""
        level = score.level.value if isinstance(score.level, MaturityLevel) else int(score.level)
        impl_status = self.LEVEL_TO_IMPLEMENTATION_STATUS.get(level, "partial")

        desc = (
            f"Maturity assessment for {score.entity_type} '{score.entity_id}': "
            f"Level {level} ({impl_status}), Score {score.score:.2f}/4.0"
        )

        if score.evidence_count > 0:
            desc += f". Based on {score.evidence_count} evidence items"

        if score.confidence < 1.0:
            desc += f" with {score.confidence * 100:.0f}% confidence"

        if trend:
            if trend.change_direction == "improving":
                desc += f". Trend: Improving (+{trend.change_amount:.2f})"
            elif trend.change_direction == "declining":
                desc += f". Trend: Declining ({trend.change_amount:.2f})"
            else:
                desc += ". Trend: Stable"

        return desc

    def _format_finding_description(self, score: MaturityScore) -> str:
        """Format finding description for low maturity or missing evidence."""
        level = score.level.value if isinstance(score.level, MaturityLevel) else int(score.level)

        desc = (
            f"Maturity gap identified for {score.entity_type} '{score.entity_id}'. "
            f"Current level: {level}, Target level: {self.config.satisfied_threshold}"
        )

        gap = self.config.satisfied_threshold - level
        if gap > 0:
            desc += f". Gap: {gap} level(s) below target"

        if score.missing_evidence_types:
            missing = ", ".join(score.missing_evidence_types[:5])
            desc += f". Missing evidence types: {missing}"

        # Add recommended actions
        if level == 0:
            desc += ". Recommendation: Establish initial processes and documentation"
        elif level == 1:
            desc += ". Recommendation: Document and standardize existing processes"
        else:
            desc += ". Recommendation: Improve automation and monitoring"

        return desc

    def map_level_to_implementation_status(self, level: int) -> str:
        """
        Map a maturity level to OSCAL implementation status.

        Args:
            level: Maturity level (0-4)

        Returns:
            OSCAL implementation status
        """
        return self.LEVEL_TO_IMPLEMENTATION_STATUS.get(level, "partial")

    def get_findings_by_entity_type(
        self,
        findings: list[Finding],
    ) -> dict[str, list[Finding]]:
        """
        Group findings by entity type.

        Args:
            findings: List of OSCAL findings

        Returns:
            Dictionary mapping entity types to findings
        """
        by_type: dict[str, list[Finding]] = {}

        for finding in findings:
            entity_type = "unknown"
            if finding.props:
                for prop in finding.props:
                    if prop.name == "entity-type":
                        entity_type = prop.value
                        break

            if entity_type not in by_type:
                by_type[entity_type] = []
            by_type[entity_type].append(finding)

        return by_type

    def get_findings_by_maturity_gap(
        self,
        findings: list[Finding],
    ) -> dict[int, list[Finding]]:
        """
        Group findings by maturity gap size.

        Args:
            findings: List of OSCAL findings

        Returns:
            Dictionary mapping gap size to findings
        """
        by_gap: dict[int, list[Finding]] = {}

        for finding in findings:
            gap = 0
            if finding.props:
                for prop in finding.props:
                    if prop.name == "maturity-gap":
                        gap = int(prop.value)
                        break

            if gap not in by_gap:
                by_gap[gap] = []
            by_gap[gap].append(finding)

        return by_gap

    def get_summary(
        self,
        maturity_scores: list[MaturityScore],
        observations: list[Observation],
        findings: list[Finding],
    ) -> dict[str, Any]:
        """
        Get summary statistics from mapped maturity data.

        Args:
            maturity_scores: Original maturity scores
            observations: List of OSCAL observations
            findings: List of OSCAL findings

        Returns:
            Summary dictionary
        """
        # Calculate level distribution
        level_counts: dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        total_score = 0.0

        for score in maturity_scores:
            level = score.level.value if isinstance(score.level, MaturityLevel) else int(score.level)
            if level in level_counts:
                level_counts[level] += 1
            total_score += score.score

        avg_score = total_score / len(maturity_scores) if maturity_scores else 0.0

        # Count by satisfaction
        satisfied = sum(
            1 for s in maturity_scores
            if (s.level.value if isinstance(s.level, MaturityLevel) else int(s.level)) >= self.config.satisfied_threshold
        )
        unsatisfied = len(maturity_scores) - satisfied

        return {
            "total_assessments": len(maturity_scores),
            "total_observations": len(observations),
            "total_findings": len(findings),
            "average_score": round(avg_score, 2),
            "satisfied_count": satisfied,
            "unsatisfied_count": unsatisfied,
            "satisfaction_rate": (satisfied / len(maturity_scores) * 100) if maturity_scores else 0,
            "level_distribution": level_counts,
            "findings_by_gap": {
                gap: len(items)
                for gap, items in self.get_findings_by_maturity_gap(findings).items()
            },
        }


@dataclass
class POAMConfig:
    """Configuration for POA&M generation."""

    # Document info
    title: str = "Plan of Action and Milestones"
    description: str = "Remediation plan for compliance findings"

    # Organization info
    organization_name: str = "Organization"
    organization_uuid: UUID = field(default_factory=uuid4)

    # SSP reference
    ssp_href: str | None = None
    system_id: str | None = None
    system_id_type: str = "https://attestful.dev"

    # Timeline defaults (days from finding)
    critical_deadline_days: int = 30
    high_deadline_days: int = 60
    medium_deadline_days: int = 90
    low_deadline_days: int = 180

    # Version
    version: str = "1.0.0"


@dataclass
class RemediationTask:
    """A remediation task with timeline."""

    task_id: str
    title: str
    description: str
    responsible_party: str | None = None
    effort_estimate: str | None = None  # e.g., "2 hours", "1 day", "1 week"
    resources_needed: list[str] | None = None


class POAMGenerator:
    """
    Generate OSCAL Plan of Action and Milestones (POA&M) documents.

    Creates POA&M documents from assessment findings with:
    - Risk identification and categorization
    - Remediation timelines and milestones
    - Resource requirements
    - Responsible party assignments
    """

    # Risk level to severity mapping
    RISK_TO_SEVERITY: dict[str, str] = {
        "very-high": "critical",
        "high": "high",
        "moderate": "medium",
        "low": "low",
        "very-low": "info",
    }

    # Default remediation lifecycle
    DEFAULT_LIFECYCLE = "planned"

    def __init__(self, config: POAMConfig) -> None:
        """
        Initialize the POA&M generator.

        Args:
            config: Configuration for POA&M generation
        """
        self.config = config

    def generate(
        self,
        findings: list[Finding],
        observations: list[Observation] | None = None,
        remediation_tasks: dict[str, list[RemediationTask]] | None = None,
        responsible_parties: dict[str, str] | None = None,
    ) -> PlanOfActionAndMilestones:
        """
        Generate a POA&M document from assessment findings.

        Args:
            findings: List of findings from assessment
            observations: Optional list of related observations
            remediation_tasks: Optional mapping of finding UUID to remediation tasks
            responsible_parties: Optional mapping of finding UUID to responsible party

        Returns:
            OSCAL PlanOfActionAndMilestones document
        """
        logger.info(f"Generating POA&M: {self.config.title}")

        # Build metadata
        metadata = self._build_metadata()

        # Build import-ssp if configured
        import_ssp = None
        if self.config.ssp_href:
            import_ssp = ImportSSP(href=self.config.ssp_href)

        # Build system-id if configured
        system_id = None
        if self.config.system_id:
            system_id = SystemId(
                identifier_type=self.config.system_id_type,
                id=self.config.system_id,
            )

        # Build risks from findings
        risks = self._build_risks(findings, remediation_tasks, responsible_parties)

        # Build POA&M items from findings
        poam_items = self._build_poam_items(
            findings, risks, remediation_tasks, responsible_parties
        )

        # Create the POA&M document
        poam = PlanOfActionAndMilestones(
            metadata=metadata,
            import_ssp=import_ssp,
            system_id=system_id,
            observations=observations,
            risks=risks if risks else None,
            findings=findings if findings else None,
            poam_items=poam_items,
        )

        logger.info(
            f"Generated POA&M with {len(poam_items)} items and {len(risks)} risks"
        )

        return poam

    def _build_metadata(self) -> Metadata:
        """Build the POA&M metadata section."""
        now = datetime.now(timezone.utc)

        roles = [
            Role(
                id="poam-owner",
                title="POA&M Owner",
                description="Person responsible for tracking POA&M progress",
            ),
            Role(
                id="remediation-lead",
                title="Remediation Lead",
                description="Person responsible for implementing remediations",
            ),
        ]

        parties = [
            Party(
                uuid=self.config.organization_uuid,
                type="organization",
                name=self.config.organization_name,
            ),
        ]

        responsible_parties = [
            ResponsibleParty(
                role_id="poam-owner",
                party_uuids=[self.config.organization_uuid],
            ),
        ]

        return Metadata(
            title=self.config.title,
            last_modified=now,
            version=self.config.version,
            oscal_version="1.1.2",
            roles=roles,
            parties=parties,
            responsible_parties=responsible_parties,
            props=[
                Property(name="poam-type", value="automated"),
                Property(name="generator", value="Attestful POA&M Generator"),
            ],
        )

    def _build_risks(
        self,
        findings: list[Finding],
        remediation_tasks: dict[str, list[RemediationTask]] | None,
        responsible_parties: dict[str, str] | None,
    ) -> list[Risk]:
        """Build risks from findings."""
        risks: list[Risk] = []

        for finding in findings:
            risk = self._create_risk(finding, remediation_tasks, responsible_parties)
            risks.append(risk)

        return risks

    def _create_risk(
        self,
        finding: Finding,
        remediation_tasks: dict[str, list[RemediationTask]] | None,
        responsible_parties: dict[str, str] | None,
    ) -> Risk:
        """Create a risk from a finding."""
        finding_uuid = str(finding.uuid)

        # Determine risk level from finding properties
        risk_level = "moderate"
        severity = "medium"
        if finding.props:
            for prop in finding.props:
                if prop.name == "risk-level":
                    risk_level = prop.value
                    severity = self.RISK_TO_SEVERITY.get(risk_level, "medium")
                    break
                if prop.name == "severity":
                    severity = prop.value

        # Calculate deadline based on severity
        deadline = self._calculate_deadline(severity)

        # Build remediations if tasks provided
        remediations = None
        if remediation_tasks and finding_uuid in remediation_tasks:
            remediations = [
                self._create_response(task, responsible_parties.get(finding_uuid) if responsible_parties else None)
                for task in remediation_tasks[finding_uuid]
            ]

        return Risk(
            uuid=uuid4(),
            title=f"Risk: {finding.title}",
            description=finding.description,
            statement=f"Risk identified from {finding.title}",
            status="open",
            deadline=deadline,
            remediations=remediations,
            props=[
                Property(name="risk-level", value=risk_level),
                Property(name="severity", value=severity),
                Property(name="source-finding", value=finding_uuid),
            ],
            related_observations=finding.related_observations,
        )

    def _create_response(
        self,
        task: RemediationTask,
        responsible_party: str | None,
    ) -> Response:
        """Create a remediation response from a task."""
        props = [
            Property(name="task-id", value=task.task_id),
        ]

        if task.effort_estimate:
            props.append(Property(name="effort-estimate", value=task.effort_estimate))

        if responsible_party:
            props.append(Property(name="assigned-to", value=responsible_party))

        # Build required assets if resources specified
        required_assets = None
        if task.resources_needed:
            required_assets = [
                {
                    "uuid": str(uuid4()),
                    "description": resource,
                    "props": [{"name": "resource-type", "value": "operational"}],
                }
                for resource in task.resources_needed
            ]

        return Response(
            uuid=uuid4(),
            lifecycle=self.DEFAULT_LIFECYCLE,
            title=task.title,
            description=task.description,
            props=props,
            required_assets=required_assets,
        )

    def _build_poam_items(
        self,
        findings: list[Finding],
        risks: list[Risk],
        remediation_tasks: dict[str, list[RemediationTask]] | None,
        responsible_parties: dict[str, str] | None,
    ) -> list[PoamItem]:
        """Build POA&M items from findings and risks."""
        poam_items: list[PoamItem] = []

        # Map risks by source finding
        risk_by_finding: dict[str, Risk] = {}
        for risk in risks:
            if risk.props:
                for prop in risk.props:
                    if prop.name == "source-finding":
                        risk_by_finding[prop.value] = risk
                        break

        for finding in findings:
            finding_uuid = str(finding.uuid)
            risk = risk_by_finding.get(finding_uuid)

            poam_item = self._create_poam_item(
                finding, risk, remediation_tasks, responsible_parties
            )
            poam_items.append(poam_item)

        return poam_items

    def _create_poam_item(
        self,
        finding: Finding,
        risk: Risk | None,
        remediation_tasks: dict[str, list[RemediationTask]] | None,
        responsible_parties: dict[str, str] | None,
    ) -> PoamItem:
        """Create a POA&M item from a finding."""
        finding_uuid = str(finding.uuid)

        # Determine severity/priority
        severity = "medium"
        risk_level = "moderate"
        if finding.props:
            for prop in finding.props:
                if prop.name == "severity":
                    severity = prop.value
                elif prop.name == "risk-level":
                    risk_level = prop.value

        # Build properties
        props = [
            Property(name="status", value="open"),
            Property(name="severity", value=severity),
            Property(name="risk-level", value=risk_level),
        ]

        # Add responsible party if specified
        if responsible_parties and finding_uuid in responsible_parties:
            props.append(
                Property(name="assigned-to", value=responsible_parties[finding_uuid])
            )

        # Add deadline
        deadline = self._calculate_deadline(severity)
        props.append(
            Property(name="due-date", value=deadline.isoformat())
        )

        # Build related risks
        related_risks = None
        if risk:
            related_risks = [{"risk-uuid": str(risk.uuid)}]

        return PoamItem(
            uuid=uuid4(),
            title=finding.title,
            description=self._format_poam_description(finding, risk),
            props=props,
            related_findings=[{"finding-uuid": finding_uuid}],
            related_observations=finding.related_observations,
            related_risks=related_risks,
        )

    def _calculate_deadline(self, severity: str) -> datetime:
        """Calculate deadline based on severity."""
        now = datetime.now(timezone.utc)

        if severity in ("critical", "very-high"):
            days = self.config.critical_deadline_days
        elif severity in ("high",):
            days = self.config.high_deadline_days
        elif severity in ("medium", "moderate"):
            days = self.config.medium_deadline_days
        else:
            days = self.config.low_deadline_days

        from datetime import timedelta
        return now + timedelta(days=days)

    def _format_poam_description(
        self,
        finding: Finding,
        risk: Risk | None,
    ) -> str:
        """Format POA&M item description."""
        desc = finding.description

        if risk and risk.remediations:
            desc += "\n\nPlanned Remediations:\n"
            for i, remediation in enumerate(risk.remediations, 1):
                desc += f"{i}. {remediation.title}: {remediation.description}\n"

        return desc

    def add_milestone(
        self,
        poam: PlanOfActionAndMilestones,
        poam_item_uuid: UUID,
        milestone_title: str,
        due_date: datetime,
        description: str | None = None,
    ) -> Milestone:
        """
        Add a milestone to a POA&M item.

        Note: OSCAL POA&M items don't directly contain milestones,
        but we can track them via properties or related tasks.
        This method returns a Milestone object for tracking purposes.

        Args:
            poam: The POA&M document
            poam_item_uuid: UUID of the POA&M item
            milestone_title: Title of the milestone
            due_date: Due date for the milestone
            description: Optional description

        Returns:
            The created Milestone object
        """
        milestone = Milestone(
            uuid=uuid4(),
            title=milestone_title,
            description=description,
            due_date=due_date,
        )

        # Find the POA&M item and add milestone reference to properties
        for item in poam.poam_items:
            if item.uuid == poam_item_uuid:
                if item.props is None:
                    item.props = []
                item.props.append(
                    Property(
                        name="milestone",
                        value=f"{milestone.title} (due: {due_date.strftime('%Y-%m-%d')})",
                    )
                )
                break

        return milestone

    def update_item_status(
        self,
        poam: PlanOfActionAndMilestones,
        poam_item_uuid: UUID,
        new_status: str,
        remarks: str | None = None,
    ) -> None:
        """
        Update the status of a POA&M item.

        Args:
            poam: The POA&M document
            poam_item_uuid: UUID of the POA&M item
            new_status: New status (e.g., "open", "in-progress", "completed", "risk-accepted")
            remarks: Optional remarks about the status change
        """
        for item in poam.poam_items:
            if item.uuid == poam_item_uuid:
                # Update status property
                if item.props is None:
                    item.props = []

                for prop in item.props:
                    if prop.name == "status":
                        prop.value = new_status
                        break
                else:
                    item.props.append(Property(name="status", value=new_status))

                # Add status change timestamp
                item.props.append(
                    Property(
                        name="status-updated",
                        value=datetime.now(timezone.utc).isoformat(),
                    )
                )

                if remarks:
                    item.remarks = remarks

                break

    def get_summary(self, poam: PlanOfActionAndMilestones) -> dict[str, Any]:
        """
        Get summary statistics from a POA&M.

        Args:
            poam: The POA&M document

        Returns:
            Summary dictionary
        """
        status_counts: dict[str, int] = {
            "open": 0,
            "in-progress": 0,
            "completed": 0,
            "risk-accepted": 0,
            "other": 0,
        }

        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for item in poam.poam_items:
            status = "open"
            severity = "medium"

            if item.props:
                for prop in item.props:
                    if prop.name == "status":
                        status = prop.value
                    elif prop.name == "severity":
                        severity = prop.value

            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts["other"] += 1

            if severity in severity_counts:
                severity_counts[severity] += 1

        total_items = len(poam.poam_items)
        completed = status_counts.get("completed", 0)

        return {
            "title": poam.metadata.title,
            "total_items": total_items,
            "total_risks": len(poam.risks) if poam.risks else 0,
            "status_distribution": status_counts,
            "severity_distribution": severity_counts,
            "completion_rate": (completed / total_items * 100) if total_items > 0 else 0,
            "open_items": status_counts.get("open", 0),
            "critical_items": severity_counts.get("critical", 0),
            "high_priority_items": severity_counts.get("critical", 0) + severity_counts.get("high", 0),
        }

    def save(
        self,
        poam: PlanOfActionAndMilestones,
        path: str | Path,
        format: str = "json",
    ) -> Path:
        """
        Save the POA&M document to a file.

        Args:
            poam: The POA&M document
            path: Output file path
            format: Output format ("json" or "yaml")

        Returns:
            Path to the saved file
        """
        path = Path(path)

        if format == "json":
            content = '{"plan-of-action-and-milestones": ' + poam.to_json() + "}"
            if not path.suffix:
                path = path.with_suffix(".json")
        elif format == "yaml":
            data = {
                "plan-of-action-and-milestones": poam.model_dump(
                    by_alias=True, exclude_none=True, mode="json"
                )
            }
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)
            if not path.suffix:
                path = path.with_suffix(".yaml")
        else:
            raise OSCALError(f"Unsupported format: {format}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        logger.info(f"Saved POA&M to {path}")
        return path


def create_poam_from_findings(
    title: str,
    findings: list[Finding],
    observations: list[Observation] | None = None,
    **kwargs: Any,
) -> PlanOfActionAndMilestones:
    """
    Convenience function to create a POA&M from findings.

    Args:
        title: POA&M title
        findings: List of findings from assessment
        observations: Optional related observations
        **kwargs: Additional POAMConfig parameters

    Returns:
        Generated PlanOfActionAndMilestones
    """
    config = POAMConfig(title=title, **kwargs)
    generator = POAMGenerator(config)
    return generator.generate(findings, observations)


@dataclass
class AssessmentSnapshot:
    """A point-in-time snapshot of assessment results."""

    assessment_id: str
    assessment_date: datetime
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    pass_rate: float = 0.0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    controls_assessed: int = 0
    poam_items_open: int = 0
    poam_items_completed: int = 0
    maturity_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "assessment_id": self.assessment_id,
            "assessment_date": self.assessment_date.isoformat(),
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "pass_rate": self.pass_rate,
            "findings_by_severity": self.findings_by_severity,
            "controls_assessed": self.controls_assessed,
            "poam_items_open": self.poam_items_open,
            "poam_items_completed": self.poam_items_completed,
            "maturity_score": self.maturity_score,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssessmentSnapshot:
        """Create from dictionary."""
        return cls(
            assessment_id=data["assessment_id"],
            assessment_date=datetime.fromisoformat(data["assessment_date"]),
            total_checks=data.get("total_checks", 0),
            passed_checks=data.get("passed_checks", 0),
            failed_checks=data.get("failed_checks", 0),
            pass_rate=data.get("pass_rate", 0.0),
            findings_by_severity=data.get("findings_by_severity", {}),
            controls_assessed=data.get("controls_assessed", 0),
            poam_items_open=data.get("poam_items_open", 0),
            poam_items_completed=data.get("poam_items_completed", 0),
            maturity_score=data.get("maturity_score"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AssessmentComparison:
    """Comparison between two assessment snapshots."""

    baseline: AssessmentSnapshot
    current: AssessmentSnapshot
    pass_rate_change: float = 0.0
    findings_change: dict[str, int] = field(default_factory=dict)
    poam_progress: float = 0.0
    maturity_change: float | None = None
    trend_direction: str = "stable"  # "improving", "declining", "stable"
    days_between: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "baseline_id": self.baseline.assessment_id,
            "baseline_date": self.baseline.assessment_date.isoformat(),
            "current_id": self.current.assessment_id,
            "current_date": self.current.assessment_date.isoformat(),
            "pass_rate_change": self.pass_rate_change,
            "findings_change": self.findings_change,
            "poam_progress": self.poam_progress,
            "maturity_change": self.maturity_change,
            "trend_direction": self.trend_direction,
            "days_between": self.days_between,
        }


@dataclass
class ComplianceTrajectory:
    """Projected compliance trajectory based on historical data."""

    current_pass_rate: float
    projected_pass_rate_30d: float | None = None
    projected_pass_rate_60d: float | None = None
    projected_pass_rate_90d: float | None = None
    trend_slope: float = 0.0  # Rate of change per day
    confidence: float = 0.0  # Confidence in projection (0-1)
    days_to_target: int | None = None  # Days to reach target pass rate
    risk_level: str = "moderate"  # Based on trajectory


class AssessmentHistoryTracker:
    """
    Track assessment results over time for trend analysis.

    Provides:
    - Trend analysis across assessments
    - Comparison between assessment dates
    - Progress tracking on POA&M items
    - Compliance trajectory visualization
    """

    def __init__(self, storage_path: str | Path | None = None) -> None:
        """
        Initialize the history tracker.

        Args:
            storage_path: Optional path to persist history
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self.snapshots: list[AssessmentSnapshot] = []

        # Load existing history if available
        if self.storage_path and self.storage_path.exists():
            self._load_history()

    def add_assessment(
        self,
        results: AssessmentResults,
        poam: PlanOfActionAndMilestones | None = None,
        maturity_scores: list[MaturityScore] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AssessmentSnapshot:
        """
        Add an assessment to the history.

        Args:
            results: Assessment results document
            poam: Optional POA&M document
            maturity_scores: Optional maturity scores
            metadata: Optional additional metadata

        Returns:
            The created snapshot
        """
        # Create snapshot from assessment results
        snapshot = self._create_snapshot(results, poam, maturity_scores, metadata)
        self.snapshots.append(snapshot)

        # Sort by date
        self.snapshots.sort(key=lambda s: s.assessment_date)

        # Persist if storage configured
        if self.storage_path:
            self._save_history()

        logger.info(f"Added assessment snapshot: {snapshot.assessment_id}")
        return snapshot

    def _create_snapshot(
        self,
        results: AssessmentResults,
        poam: PlanOfActionAndMilestones | None,
        maturity_scores: list[MaturityScore] | None,
        metadata: dict[str, Any] | None,
    ) -> AssessmentSnapshot:
        """Create a snapshot from assessment data."""
        # Get summary from results
        summary = get_assessment_summary(results)

        # Get POA&M stats if available
        poam_open = 0
        poam_completed = 0
        if poam:
            for item in poam.poam_items:
                status = "open"
                if item.props:
                    for prop in item.props:
                        if prop.name == "status":
                            status = prop.value
                            break
                if status == "completed":
                    poam_completed += 1
                else:
                    poam_open += 1

        # Calculate average maturity if scores provided
        avg_maturity = None
        if maturity_scores:
            total = sum(s.score for s in maturity_scores)
            avg_maturity = total / len(maturity_scores) if maturity_scores else None

        # Get assessment date
        assessment_date = datetime.now(timezone.utc)
        if results.results and results.results[0].start:
            assessment_date = results.results[0].start

        # Build findings by severity
        findings_by_severity: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        if results.results and results.results[0].findings:
            for finding in results.results[0].findings:
                severity = "medium"
                if finding.props:
                    for prop in finding.props:
                        if prop.name == "severity":
                            severity = prop.value.lower()
                            break
                if severity in findings_by_severity:
                    findings_by_severity[severity] += 1

        return AssessmentSnapshot(
            assessment_id=str(uuid4()),
            assessment_date=assessment_date,
            total_checks=summary.get("passed_checks", 0) + summary.get("failed_checks", 0),
            passed_checks=summary.get("passed_checks", 0),
            failed_checks=summary.get("failed_checks", 0),
            pass_rate=summary.get("pass_rate", 0.0),
            findings_by_severity=findings_by_severity,
            controls_assessed=summary.get("total_observations", 0),
            poam_items_open=poam_open,
            poam_items_completed=poam_completed,
            maturity_score=avg_maturity,
            metadata=metadata or {},
        )

    def get_latest_snapshot(self) -> AssessmentSnapshot | None:
        """Get the most recent assessment snapshot."""
        return self.snapshots[-1] if self.snapshots else None

    def get_snapshot_by_date(
        self,
        target_date: datetime,
        tolerance_days: int = 1,
    ) -> AssessmentSnapshot | None:
        """
        Get snapshot closest to the target date.

        Args:
            target_date: Target date to find
            tolerance_days: Maximum days difference allowed

        Returns:
            Closest snapshot within tolerance or None
        """
        from datetime import timedelta

        closest: AssessmentSnapshot | None = None
        min_diff = timedelta(days=tolerance_days + 1)

        for snapshot in self.snapshots:
            diff = abs(snapshot.assessment_date - target_date)
            if diff < min_diff:
                min_diff = diff
                closest = snapshot

        if closest and min_diff <= timedelta(days=tolerance_days):
            return closest
        return None

    def compare_assessments(
        self,
        baseline_id: str | None = None,
        current_id: str | None = None,
    ) -> AssessmentComparison | None:
        """
        Compare two assessments.

        Args:
            baseline_id: Baseline assessment ID (defaults to oldest)
            current_id: Current assessment ID (defaults to latest)

        Returns:
            Comparison results or None if not enough data
        """
        if len(self.snapshots) < 2:
            return None

        # Find baseline and current snapshots
        baseline = None
        current = None

        if baseline_id:
            baseline = next((s for s in self.snapshots if s.assessment_id == baseline_id), None)
        else:
            baseline = self.snapshots[0]

        if current_id:
            current = next((s for s in self.snapshots if s.assessment_id == current_id), None)
        else:
            current = self.snapshots[-1]

        if not baseline or not current:
            return None

        # Calculate changes
        pass_rate_change = current.pass_rate - baseline.pass_rate

        findings_change: dict[str, int] = {}
        for severity in ["critical", "high", "medium", "low", "info"]:
            baseline_count = baseline.findings_by_severity.get(severity, 0)
            current_count = current.findings_by_severity.get(severity, 0)
            findings_change[severity] = current_count - baseline_count

        # POA&M progress
        total_poam_baseline = baseline.poam_items_open + baseline.poam_items_completed
        poam_progress = 0.0
        if total_poam_baseline > 0:
            # Progress = items completed since baseline
            completed_since = current.poam_items_completed - baseline.poam_items_completed
            poam_progress = (completed_since / total_poam_baseline) * 100

        # Maturity change
        maturity_change = None
        if baseline.maturity_score is not None and current.maturity_score is not None:
            maturity_change = current.maturity_score - baseline.maturity_score

        # Determine trend direction
        if pass_rate_change > 1.0:
            trend_direction = "improving"
        elif pass_rate_change < -1.0:
            trend_direction = "declining"
        else:
            trend_direction = "stable"

        # Days between assessments
        days_between = (current.assessment_date - baseline.assessment_date).days

        return AssessmentComparison(
            baseline=baseline,
            current=current,
            pass_rate_change=pass_rate_change,
            findings_change=findings_change,
            poam_progress=poam_progress,
            maturity_change=maturity_change,
            trend_direction=trend_direction,
            days_between=days_between,
        )

    def calculate_trajectory(
        self,
        target_pass_rate: float = 95.0,
    ) -> ComplianceTrajectory:
        """
        Calculate compliance trajectory based on historical data.

        Args:
            target_pass_rate: Target pass rate percentage

        Returns:
            Projected trajectory
        """
        if not self.snapshots:
            return ComplianceTrajectory(
                current_pass_rate=0.0,
                risk_level="very-high",
            )

        current = self.snapshots[-1]

        if len(self.snapshots) < 2:
            # Not enough data for projection
            return ComplianceTrajectory(
                current_pass_rate=current.pass_rate,
                confidence=0.0,
                risk_level=self._calculate_risk_level(current.pass_rate),
            )

        # Calculate trend slope (pass rate change per day)
        # Use simple linear regression on recent snapshots
        x_values = []  # Days from first assessment
        y_values = []  # Pass rates

        first_date = self.snapshots[0].assessment_date
        for snapshot in self.snapshots:
            days = (snapshot.assessment_date - first_date).days
            x_values.append(days)
            y_values.append(snapshot.pass_rate)

        # Calculate slope
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)

        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            slope = 0.0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator

        # Project future pass rates
        current_days = x_values[-1]
        projected_30d = current.pass_rate + (slope * 30)
        projected_60d = current.pass_rate + (slope * 60)
        projected_90d = current.pass_rate + (slope * 90)

        # Clamp to 0-100 range
        projected_30d = max(0, min(100, projected_30d))
        projected_60d = max(0, min(100, projected_60d))
        projected_90d = max(0, min(100, projected_90d))

        # Calculate days to target (if improving)
        days_to_target = None
        if slope > 0 and current.pass_rate < target_pass_rate:
            days_to_target = int((target_pass_rate - current.pass_rate) / slope)
            if days_to_target < 0:
                days_to_target = None

        # Calculate confidence based on data points and variance
        confidence = min(1.0, len(self.snapshots) / 10)  # More data = more confidence

        return ComplianceTrajectory(
            current_pass_rate=current.pass_rate,
            projected_pass_rate_30d=round(projected_30d, 1),
            projected_pass_rate_60d=round(projected_60d, 1),
            projected_pass_rate_90d=round(projected_90d, 1),
            trend_slope=round(slope, 4),
            confidence=confidence,
            days_to_target=days_to_target,
            risk_level=self._calculate_risk_level(current.pass_rate, slope),
        )

    def _calculate_risk_level(
        self,
        pass_rate: float,
        slope: float = 0.0,
    ) -> str:
        """Calculate risk level based on pass rate and trend."""
        if pass_rate < 50:
            return "very-high"
        elif pass_rate < 70:
            if slope < 0:
                return "very-high"
            return "high"
        elif pass_rate < 85:
            if slope < 0:
                return "high"
            return "moderate"
        elif pass_rate < 95:
            if slope < 0:
                return "moderate"
            return "low"
        else:
            return "very-low"

    def get_trend_data(
        self,
        metric: str = "pass_rate",
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get trend data for visualization.

        Args:
            metric: Metric to track (pass_rate, findings, maturity)
            limit: Maximum number of data points

        Returns:
            List of data points for charting
        """
        snapshots = self.snapshots[-limit:] if limit else self.snapshots

        data_points = []
        for snapshot in snapshots:
            point = {
                "date": snapshot.assessment_date.isoformat(),
                "assessment_id": snapshot.assessment_id,
            }

            if metric == "pass_rate":
                point["value"] = snapshot.pass_rate
            elif metric == "findings":
                point["value"] = snapshot.failed_checks
                point["by_severity"] = snapshot.findings_by_severity
            elif metric == "maturity":
                point["value"] = snapshot.maturity_score or 0
            elif metric == "poam":
                point["open"] = snapshot.poam_items_open
                point["completed"] = snapshot.poam_items_completed
                total = snapshot.poam_items_open + snapshot.poam_items_completed
                point["value"] = (snapshot.poam_items_completed / total * 100) if total > 0 else 0
            else:
                point["value"] = getattr(snapshot, metric, 0)

            data_points.append(point)

        return data_points

    def get_summary(self) -> dict[str, Any]:
        """Get summary of assessment history."""
        if not self.snapshots:
            return {
                "total_assessments": 0,
                "status": "no-data",
            }

        latest = self.snapshots[-1]
        trajectory = self.calculate_trajectory()
        comparison = self.compare_assessments() if len(self.snapshots) >= 2 else None

        # Calculate assessment frequency
        if len(self.snapshots) >= 2:
            total_days = (self.snapshots[-1].assessment_date - self.snapshots[0].assessment_date).days
            avg_frequency = total_days / (len(self.snapshots) - 1) if len(self.snapshots) > 1 else 0
        else:
            avg_frequency = 0

        return {
            "total_assessments": len(self.snapshots),
            "first_assessment": self.snapshots[0].assessment_date.isoformat(),
            "latest_assessment": latest.assessment_date.isoformat(),
            "current_pass_rate": latest.pass_rate,
            "current_findings": latest.failed_checks,
            "trend_direction": comparison.trend_direction if comparison else "unknown",
            "trend_slope": trajectory.trend_slope,
            "risk_level": trajectory.risk_level,
            "days_to_95_percent": trajectory.days_to_target,
            "avg_assessment_frequency_days": round(avg_frequency, 1),
            "poam_completion_rate": (
                latest.poam_items_completed / (latest.poam_items_open + latest.poam_items_completed) * 100
                if (latest.poam_items_open + latest.poam_items_completed) > 0
                else 0
            ),
        }

    def _save_history(self) -> None:
        """Save history to storage."""
        if not self.storage_path:
            return

        data = {
            "version": "1.0",
            "snapshots": [s.to_dict() for s in self.snapshots],
        }

        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        content = orjson.dumps(data, option=orjson.OPT_INDENT_2)
        self.storage_path.write_bytes(content)

        logger.debug(f"Saved assessment history to {self.storage_path}")

    def _load_history(self) -> None:
        """Load history from storage."""
        if not self.storage_path or not self.storage_path.exists():
            return

        try:
            data = orjson.loads(self.storage_path.read_bytes())
            self.snapshots = [
                AssessmentSnapshot.from_dict(s)
                for s in data.get("snapshots", [])
            ]
            logger.debug(f"Loaded {len(self.snapshots)} assessment snapshots")
        except Exception as e:
            logger.warning(f"Failed to load assessment history: {e}")
            self.snapshots = []

    def clear_history(self) -> None:
        """Clear all history."""
        self.snapshots = []
        if self.storage_path and self.storage_path.exists():
            self.storage_path.unlink()

    def export_history(self, path: str | Path, format: str = "json") -> Path:
        """
        Export history to a file.

        Args:
            path: Output file path
            format: Output format ("json" or "yaml")

        Returns:
            Path to exported file
        """
        path = Path(path)

        data = {
            "version": "1.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "snapshots": [s.to_dict() for s in self.snapshots],
            "summary": self.get_summary(),
        }

        if format == "json":
            content = orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()
            if not path.suffix:
                path = path.with_suffix(".json")
        elif format == "yaml":
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)
            if not path.suffix:
                path = path.with_suffix(".yaml")
        else:
            raise OSCALError(f"Unsupported format: {format}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        logger.info(f"Exported assessment history to {path}")
        return path
