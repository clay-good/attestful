"""
Gap analysis for compliance frameworks.

Identifies missing controls, evidence gaps, and remediation priorities.
Supports SOC 2, NIST 800-53, ISO 27001, and HITRUST frameworks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger
from attestful.core.models import CheckResult

logger = get_logger(__name__)


class GapSeverity(str, Enum):
    """Severity levels for compliance gaps."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ComplianceGap:
    """
    Represents a gap in compliance coverage.

    Attributes:
        control_id: Control or requirement identifier.
        framework: Framework this gap relates to.
        severity: Gap severity.
        gap_type: Type of gap (missing_evidence, failed_check, no_automation).
        title: Short description of the gap.
        description: Detailed description.
        remediation: Recommended remediation steps.
        affected_resources: List of affected resource IDs.
        related_checks: Related check IDs.
        detected_at: When this gap was detected.
    """

    control_id: str
    framework: str
    severity: GapSeverity
    gap_type: str
    title: str
    description: str
    remediation: str = ""
    affected_resources: list[str] = field(default_factory=list)
    related_checks: list[str] = field(default_factory=list)
    detected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "framework": self.framework,
            "severity": self.severity.value,
            "gap_type": self.gap_type,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "affected_resources": self.affected_resources,
            "related_checks": self.related_checks,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class GapAnalysisResult:
    """
    Result of a gap analysis.

    Attributes:
        framework: Framework analyzed.
        total_gaps: Total number of gaps found.
        gaps_by_severity: Count of gaps by severity.
        gaps: List of identified gaps.
        coverage_rate: Percentage of controls with evidence/checks.
        analyzed_at: When this analysis was performed.
    """

    framework: str
    total_gaps: int
    gaps_by_severity: dict[str, int]
    gaps: list[ComplianceGap]
    coverage_rate: float
    analyzed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "total_gaps": self.total_gaps,
            "gaps_by_severity": self.gaps_by_severity,
            "coverage_rate": self.coverage_rate,
            "analyzed_at": self.analyzed_at.isoformat(),
            "gaps": [g.to_dict() for g in self.gaps],
        }


class GapAnalyzer:
    """
    Analyze compliance gaps across frameworks.

    Identifies:
    - Controls without evidence
    - Failing compliance checks
    - Areas lacking automated coverage
    - Cross-framework mapping gaps

    Example:
        analyzer = GapAnalyzer(framework="soc2")
        analyzer.add_check_results(results)

        gaps = analyzer.analyze()
        for gap in gaps.gaps:
            print(f"{gap.severity}: {gap.title}")
    """

    # SOC 2 Trust Services Criteria structure
    SOC2_CONTROLS = {
        "CC1": {
            "name": "Control Environment",
            "controls": ["CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5"],
        },
        "CC2": {
            "name": "Communication and Information",
            "controls": ["CC2.1", "CC2.2", "CC2.3"],
        },
        "CC3": {
            "name": "Risk Assessment",
            "controls": ["CC3.1", "CC3.2", "CC3.3", "CC3.4"],
        },
        "CC4": {
            "name": "Monitoring Activities",
            "controls": ["CC4.1", "CC4.2"],
        },
        "CC5": {
            "name": "Control Activities",
            "controls": ["CC5.1", "CC5.2", "CC5.3"],
        },
        "CC6": {
            "name": "Logical and Physical Access Controls",
            "controls": ["CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7", "CC6.8"],
        },
        "CC7": {
            "name": "System Operations",
            "controls": ["CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5"],
        },
        "CC8": {
            "name": "Change Management",
            "controls": ["CC8.1"],
        },
        "CC9": {
            "name": "Risk Mitigation",
            "controls": ["CC9.1", "CC9.2"],
        },
        "A1": {
            "name": "Availability",
            "controls": ["A1.1", "A1.2", "A1.3"],
        },
        "C1": {
            "name": "Confidentiality",
            "controls": ["C1.1", "C1.2"],
        },
        "PI1": {
            "name": "Processing Integrity",
            "controls": ["PI1.1", "PI1.2", "PI1.3", "PI1.4", "PI1.5"],
        },
        "P1": {
            "name": "Privacy",
            "controls": ["P1.1"],
        },
    }

    # NIST 800-53 control families
    NIST_800_53_FAMILIES = {
        "AC": {"name": "Access Control", "count": 25},
        "AT": {"name": "Awareness and Training", "count": 6},
        "AU": {"name": "Audit and Accountability", "count": 16},
        "CA": {"name": "Assessment, Authorization, Monitoring", "count": 9},
        "CM": {"name": "Configuration Management", "count": 14},
        "CP": {"name": "Contingency Planning", "count": 13},
        "IA": {"name": "Identification and Authentication", "count": 12},
        "IR": {"name": "Incident Response", "count": 10},
        "MA": {"name": "Maintenance", "count": 7},
        "MP": {"name": "Media Protection", "count": 8},
        "PE": {"name": "Physical and Environmental Protection", "count": 23},
        "PL": {"name": "Planning", "count": 11},
        "PM": {"name": "Program Management", "count": 32},
        "PS": {"name": "Personnel Security", "count": 9},
        "PT": {"name": "PII Processing and Transparency", "count": 8},
        "RA": {"name": "Risk Assessment", "count": 10},
        "SA": {"name": "System and Services Acquisition", "count": 23},
        "SC": {"name": "System and Communications Protection", "count": 51},
        "SI": {"name": "System and Information Integrity", "count": 23},
        "SR": {"name": "Supply Chain Risk Management", "count": 12},
    }

    # ISO 27001:2022 Annex A domains
    ISO_27001_DOMAINS = {
        "A.5": {"name": "Organizational controls", "count": 37},
        "A.6": {"name": "People controls", "count": 8},
        "A.7": {"name": "Physical controls", "count": 14},
        "A.8": {"name": "Technological controls", "count": 34},
    }

    # HITRUST CSF categories
    HITRUST_CATEGORIES = {
        "00": {"name": "Information Security Management Program", "count": 0},
        "01": {"name": "Access Control", "count": 25},
        "02": {"name": "Human Resources Security", "count": 0},
        "03": {"name": "Risk Management", "count": 0},
        "04": {"name": "Security Policy", "count": 0},
        "05": {"name": "Organization of Information Security", "count": 0},
        "06": {"name": "Compliance", "count": 0},
        "07": {"name": "Asset Management", "count": 0},
        "08": {"name": "Physical and Environmental Security", "count": 0},
        "09": {"name": "Communications and Operations Management", "count": 32},
        "10": {"name": "Information Systems Acquisition, Development, Maintenance", "count": 16},
        "11": {"name": "Information Security Incident Management", "count": 5},
        "12": {"name": "Business Continuity Management", "count": 0},
        "13": {"name": "Privacy Practices", "count": 0},
    }

    def __init__(self, framework: str = "soc2") -> None:
        """
        Initialize the gap analyzer.

        Args:
            framework: Framework to analyze gaps for.
        """
        self.framework = framework
        self._check_results: list[CheckResult] = []
        self._control_checks: dict[str, list[CheckResult]] = {}

    def add_check_results(self, results: list[CheckResult]) -> None:
        """
        Add check results for gap analysis.

        Args:
            results: List of check results.
        """
        self._check_results.extend(results)

        # Map results to controls
        for result in results:
            mappings = result.check.framework_mappings or {}
            control_ids = mappings.get(self.framework, [])

            for control_id in control_ids:
                if control_id not in self._control_checks:
                    self._control_checks[control_id] = []
                self._control_checks[control_id].append(result)

    def analyze(self) -> GapAnalysisResult:
        """
        Perform gap analysis.

        Returns:
            GapAnalysisResult with identified gaps.
        """
        gaps: list[ComplianceGap] = []

        if self.framework == "soc2":
            gaps.extend(self._analyze_soc2())
        elif self.framework == "nist-800-53":
            gaps.extend(self._analyze_nist_800_53())
        elif self.framework == "iso-27001":
            gaps.extend(self._analyze_iso_27001())
        elif self.framework == "hitrust":
            gaps.extend(self._analyze_hitrust())
        else:
            gaps.extend(self._analyze_generic())

        # Count by severity
        gaps_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for gap in gaps:
            gaps_by_severity[gap.severity.value] += 1

        # Calculate coverage
        all_controls = self._get_all_controls()
        covered_controls = set(self._control_checks.keys())
        coverage_rate = (
            len(covered_controls) / len(all_controls) * 100
            if all_controls else 0
        )

        return GapAnalysisResult(
            framework=self.framework,
            total_gaps=len(gaps),
            gaps_by_severity=gaps_by_severity,
            gaps=gaps,
            coverage_rate=coverage_rate,
        )

    def _get_all_controls(self) -> set[str]:
        """Get all controls for the framework."""
        if self.framework == "soc2":
            controls = set()
            for category in self.SOC2_CONTROLS.values():
                controls.update(category["controls"])
            return controls
        elif self.framework == "nist-800-53":
            return self._get_nist_800_53_controls()
        elif self.framework == "iso-27001":
            return self._get_iso_27001_controls()
        elif self.framework == "hitrust":
            return self._get_hitrust_controls()
        return set()

    def _get_nist_800_53_controls(self) -> set[str]:
        """Get NIST 800-53 control IDs from framework module."""
        try:
            from attestful.frameworks.nist_800_53 import NIST_800_53_CONTROLS
            return set(NIST_800_53_CONTROLS.keys())
        except ImportError:
            logger.warning("NIST 800-53 framework not available")
            return set()

    def _get_iso_27001_controls(self) -> set[str]:
        """Get ISO 27001 control IDs from framework module."""
        try:
            from attestful.frameworks.iso_27001 import ISO_27001_CONTROLS
            return set(ISO_27001_CONTROLS.keys())
        except ImportError:
            logger.warning("ISO 27001 framework not available")
            return set()

    def _get_hitrust_controls(self) -> set[str]:
        """Get HITRUST control IDs from framework module."""
        try:
            from attestful.frameworks.hitrust import HITRUST_CONTROLS
            return set(HITRUST_CONTROLS.keys())
        except ImportError:
            logger.warning("HITRUST framework not available")
            return set()

    def _analyze_soc2(self) -> list[ComplianceGap]:
        """Analyze SOC 2 gaps."""
        gaps: list[ComplianceGap] = []

        for category_id, category_data in self.SOC2_CONTROLS.items():
            for control_id in category_data["controls"]:
                control_gaps = self._analyze_control(
                    control_id=control_id,
                    category_name=category_data["name"],
                )
                gaps.extend(control_gaps)

        return gaps

    def _analyze_nist_800_53(self) -> list[ComplianceGap]:
        """Analyze NIST 800-53 gaps."""
        gaps: list[ComplianceGap] = []

        try:
            from attestful.frameworks.nist_800_53 import NIST_800_53_CONTROLS

            for control_id, control in NIST_800_53_CONTROLS.items():
                family = control_id.split("-")[0]
                family_name = self.NIST_800_53_FAMILIES.get(
                    family, {"name": family}
                )["name"]
                control_gaps = self._analyze_control(
                    control_id=control_id,
                    category_name=family_name,
                )
                gaps.extend(control_gaps)
        except ImportError:
            logger.warning("NIST 800-53 framework not available for gap analysis")

        return gaps

    def _analyze_iso_27001(self) -> list[ComplianceGap]:
        """Analyze ISO 27001 gaps."""
        gaps: list[ComplianceGap] = []

        try:
            from attestful.frameworks.iso_27001 import ISO_27001_CONTROLS

            for control_id, control in ISO_27001_CONTROLS.items():
                domain = control.domain
                domain_name = self.ISO_27001_DOMAINS.get(
                    domain, {"name": domain}
                )["name"]
                control_gaps = self._analyze_control(
                    control_id=control_id,
                    category_name=domain_name,
                )
                gaps.extend(control_gaps)
        except ImportError:
            logger.warning("ISO 27001 framework not available for gap analysis")

        return gaps

    def _analyze_hitrust(self) -> list[ComplianceGap]:
        """Analyze HITRUST gaps."""
        gaps: list[ComplianceGap] = []

        try:
            from attestful.frameworks.hitrust import HITRUST_CONTROLS

            for control_id, control in HITRUST_CONTROLS.items():
                category = control.category
                category_name = self.HITRUST_CATEGORIES.get(
                    category, {"name": f"Category {category}"}
                )["name"]
                control_gaps = self._analyze_control(
                    control_id=control_id,
                    category_name=category_name,
                )
                gaps.extend(control_gaps)
        except ImportError:
            logger.warning("HITRUST framework not available for gap analysis")

        return gaps

    def _analyze_generic(self) -> list[ComplianceGap]:
        """Generic gap analysis based on check results."""
        gaps: list[ComplianceGap] = []

        # Find failing checks
        for result in self._check_results:
            if not result.passed:
                gaps.append(ComplianceGap(
                    control_id=result.check.id,
                    framework=self.framework,
                    severity=self._map_severity(result.check.severity),
                    gap_type="failed_check",
                    title=f"Failed: {result.check.title}",
                    description=result.check.description,
                    remediation=result.details.get("remediation", ""),
                    affected_resources=[result.resource_id],
                    related_checks=[result.check.id],
                ))

        return gaps

    def _analyze_control(
        self,
        control_id: str,
        category_name: str,
    ) -> list[ComplianceGap]:
        """Analyze a single control for gaps."""
        gaps: list[ComplianceGap] = []
        checks = self._control_checks.get(control_id, [])

        # No coverage gap
        if not checks:
            gaps.append(ComplianceGap(
                control_id=control_id,
                framework=self.framework,
                severity=GapSeverity.MEDIUM,
                gap_type="no_coverage",
                title=f"No automated checks for {control_id}",
                description=(
                    f"Control {control_id} ({category_name}) has no automated "
                    f"compliance checks configured."
                ),
                remediation=(
                    f"Implement automated checks for {control_id} or collect "
                    f"manual evidence to demonstrate compliance."
                ),
            ))
            return gaps

        # Check for failures
        failed_checks = [c for c in checks if not c.passed]
        if failed_checks:
            affected_resources = list(set(c.resource_id for c in failed_checks))
            failed_check_ids = list(set(c.check.id for c in failed_checks))

            # Determine severity based on number of failures
            if len(failed_checks) >= 5:
                severity = GapSeverity.CRITICAL
            elif len(failed_checks) >= 3:
                severity = GapSeverity.HIGH
            else:
                severity = GapSeverity.MEDIUM

            gaps.append(ComplianceGap(
                control_id=control_id,
                framework=self.framework,
                severity=severity,
                gap_type="failed_check",
                title=f"{len(failed_checks)} failing checks for {control_id}",
                description=(
                    f"Control {control_id} ({category_name}) has "
                    f"{len(failed_checks)} failing compliance checks "
                    f"affecting {len(affected_resources)} resources."
                ),
                remediation=(
                    f"Review and remediate the {len(failed_checks)} failing "
                    f"checks to achieve compliance with {control_id}."
                ),
                affected_resources=affected_resources,
                related_checks=failed_check_ids,
            ))

        return gaps

    @staticmethod
    def _map_severity(check_severity: str) -> GapSeverity:
        """Map check severity to gap severity."""
        mapping = {
            "critical": GapSeverity.CRITICAL,
            "high": GapSeverity.HIGH,
            "medium": GapSeverity.MEDIUM,
            "low": GapSeverity.LOW,
            "info": GapSeverity.LOW,
        }
        return mapping.get(check_severity, GapSeverity.MEDIUM)

    def get_remediation_plan(
        self,
        result: GapAnalysisResult,
        *,
        max_items: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate a prioritized remediation plan.

        Args:
            result: Gap analysis result.
            max_items: Maximum number of items to include.

        Returns:
            List of remediation items sorted by priority.
        """
        # Sort gaps by severity
        severity_order = {
            GapSeverity.CRITICAL: 0,
            GapSeverity.HIGH: 1,
            GapSeverity.MEDIUM: 2,
            GapSeverity.LOW: 3,
        }

        sorted_gaps = sorted(
            result.gaps,
            key=lambda g: (severity_order[g.severity], -len(g.affected_resources)),
        )

        plan = []
        for i, gap in enumerate(sorted_gaps[:max_items], 1):
            plan.append({
                "priority": i,
                "control_id": gap.control_id,
                "severity": gap.severity.value,
                "title": gap.title,
                "remediation": gap.remediation,
                "affected_resources_count": len(gap.affected_resources),
                "effort_estimate": self._estimate_effort(gap),
            })

        return plan

    @staticmethod
    def _estimate_effort(gap: ComplianceGap) -> str:
        """Estimate remediation effort."""
        resource_count = len(gap.affected_resources)

        if gap.gap_type == "no_coverage":
            return "medium"  # Need to implement checks
        elif resource_count > 10:
            return "high"
        elif resource_count > 3:
            return "medium"
        else:
            return "low"
