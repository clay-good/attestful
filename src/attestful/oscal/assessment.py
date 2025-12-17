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
from attestful.core.models import CheckResult, CheckStatus, Evidence
from attestful.oscal.models import (
    AssessmentResults,
    BackMatter,
    Finding,
    FindingTarget,
    ImportAP,
    LocalDefinitions,
    Metadata,
    Observation,
    Origin,
    Party,
    Property,
    RelevantEvidence,
    ResponsibleParty,
    Result,
    Role,
    Subject,
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
