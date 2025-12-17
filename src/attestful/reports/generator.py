"""
Report generator for Attestful.

Generates compliance reports in multiple formats including HTML, JSON,
and OSCAL Assessment Results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from attestful.analysis.gaps import GapAnalysisResult
from attestful.analysis.maturity import FrameworkMaturity
from attestful.core.logging import get_logger
from attestful.core.models import CheckResult

logger = get_logger(__name__)


class ReportFormat(str, Enum):
    """Supported report formats."""

    HTML = "html"
    JSON = "json"
    OSCAL = "oscal"
    MARKDOWN = "markdown"


@dataclass
class ComplianceReport:
    """
    Compliance report data.

    Attributes:
        id: Unique report ID.
        title: Report title.
        framework: Framework this report covers.
        generated_at: When the report was generated.
        period_start: Start of the assessment period.
        period_end: End of the assessment period.
        summary: Executive summary.
        maturity: Maturity assessment results.
        gaps: Gap analysis results.
        check_results: Individual check results.
        metadata: Additional report metadata.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = "Compliance Assessment Report"
    framework: str = ""
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    period_start: datetime | None = None
    period_end: datetime | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    maturity: FrameworkMaturity | None = None
    gaps: GapAnalysisResult | None = None
    check_results: list[CheckResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "framework": self.framework,
            "generated_at": self.generated_at.isoformat(),
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "summary": self.summary,
            "maturity": self.maturity.to_dict() if self.maturity else None,
            "gaps": self.gaps.to_dict() if self.gaps else None,
            "check_results_summary": {
                "total": len(self.check_results),
                "passed": sum(1 for r in self.check_results if r.passed),
                "failed": sum(1 for r in self.check_results if not r.passed),
            },
            "metadata": self.metadata,
        }


class ReportGenerator:
    """
    Generate compliance reports in various formats.

    Supports HTML, JSON, and OSCAL Assessment Results formats.

    Example:
        generator = ReportGenerator()

        report = ComplianceReport(
            title="Q4 2024 SOC 2 Assessment",
            framework="soc2",
            maturity=maturity_result,
            gaps=gap_result,
            check_results=check_results,
        )

        # Generate HTML report
        generator.generate(report, output_path, format=ReportFormat.HTML)

        # Generate OSCAL Assessment Results
        generator.generate(report, output_path, format=ReportFormat.OSCAL)
    """

    def __init__(
        self,
        *,
        company_name: str | None = None,
        company_logo: Path | None = None,
    ) -> None:
        """
        Initialize the report generator.

        Args:
            company_name: Company name for report branding.
            company_logo: Path to company logo for HTML reports.
        """
        self.company_name = company_name
        self.company_logo = company_logo

    def generate(
        self,
        report: ComplianceReport,
        output_path: Path,
        *,
        format: ReportFormat = ReportFormat.HTML,
    ) -> Path:
        """
        Generate a report in the specified format.

        Args:
            report: Report data.
            output_path: Output file path.
            format: Report format.

        Returns:
            Path to the generated report.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == ReportFormat.HTML:
            return self._generate_html(report, output_path)
        elif format == ReportFormat.JSON:
            return self._generate_json(report, output_path)
        elif format == ReportFormat.OSCAL:
            return self._generate_oscal(report, output_path)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(report, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_html(self, report: ComplianceReport, output_path: Path) -> Path:
        """Generate HTML report."""
        html = self._build_html(report)
        output_path.write_text(html)
        logger.info(f"Generated HTML report: {output_path}")
        return output_path

    def _generate_json(self, report: ComplianceReport, output_path: Path) -> Path:
        """Generate JSON report."""
        data = report.to_dict()

        # Add detailed check results
        data["check_results"] = [
            {
                "check_id": r.check.id,
                "check_title": r.check.title,
                "resource_id": r.resource_id,
                "resource_type": r.resource_type,
                "passed": r.passed,
                "severity": r.check.severity,
                "evaluated_at": r.evaluated_at.isoformat(),
            }
            for r in report.check_results
        ]

        output_path.write_text(json.dumps(data, indent=2))
        logger.info(f"Generated JSON report: {output_path}")
        return output_path

    def _generate_oscal(self, report: ComplianceReport, output_path: Path) -> Path:
        """Generate OSCAL Assessment Results."""
        oscal_ar = self._build_oscal_assessment_results(report)
        output_path.write_text(json.dumps(oscal_ar, indent=2))
        logger.info(f"Generated OSCAL Assessment Results: {output_path}")
        return output_path

    def _generate_markdown(self, report: ComplianceReport, output_path: Path) -> Path:
        """Generate Markdown report."""
        md = self._build_markdown(report)
        output_path.write_text(md)
        logger.info(f"Generated Markdown report: {output_path}")
        return output_path

    def _build_html(self, report: ComplianceReport) -> str:
        """Build HTML report content."""
        # Calculate summary stats
        total_checks = len(report.check_results)
        passed_checks = sum(1 for r in report.check_results if r.passed)
        failed_checks = total_checks - passed_checks
        pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        # Build category rows for maturity
        maturity_rows = ""
        if report.maturity:
            for cat in report.maturity.category_scores:
                level_class = cat.level.name.lower()
                maturity_rows += f"""
                <tr>
                    <td>{cat.category_id}</td>
                    <td>{cat.name}</td>
                    <td>{cat.score:.1f}</td>
                    <td class="level-{level_class}">{cat.level.name}</td>
                    <td>{cat.implementation_rate:.0f}%</td>
                </tr>
                """

        # Build gap rows
        gap_rows = ""
        if report.gaps:
            for gap in report.gaps.gaps[:20]:  # Top 20 gaps
                severity_class = gap.severity.value
                gap_rows += f"""
                <tr class="severity-{severity_class}">
                    <td>{gap.control_id}</td>
                    <td><span class="badge {severity_class}">{gap.severity.value.upper()}</span></td>
                    <td>{gap.title}</td>
                    <td>{len(gap.affected_resources)}</td>
                </tr>
                """

        # Build failed checks rows
        failed_rows = ""
        for result in report.check_results:
            if not result.passed:
                failed_rows += f"""
                <tr>
                    <td>{result.check.id}</td>
                    <td>{result.check.title}</td>
                    <td>{result.resource_id}</td>
                    <td><span class="badge {result.check.severity}">{result.check.severity.upper()}</span></td>
                </tr>
                """

        company_header = f"<h2>{self.company_name}</h2>" if self.company_name else ""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>
        :root {{
            --primary: #2563eb;
            --success: #16a34a;
            --warning: #d97706;
            --danger: #dc2626;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-700: #374151;
            --gray-900: #111827;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--gray-700);
            background: var(--gray-50);
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: white;
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        header h1 {{ color: var(--gray-900); margin-bottom: 0.5rem; }}
        header p {{ color: var(--gray-700); }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{ font-size: 0.875rem; color: var(--gray-700); margin-bottom: 0.5rem; }}
        .stat-card .value {{ font-size: 2rem; font-weight: 700; color: var(--gray-900); }}
        .stat-card .value.success {{ color: var(--success); }}
        .stat-card .value.danger {{ color: var(--danger); }}
        .stat-card .value.warning {{ color: var(--warning); }}
        section {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        section h2 {{ color: var(--gray-900); margin-bottom: 1rem; border-bottom: 2px solid var(--gray-200); padding-bottom: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--gray-200); }}
        th {{ background: var(--gray-100); font-weight: 600; }}
        tr:hover {{ background: var(--gray-50); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: #fef2f2; color: #991b1b; }}
        .badge.high {{ background: #fff7ed; color: #c2410c; }}
        .badge.medium {{ background: #fefce8; color: #a16207; }}
        .badge.low {{ background: #f0fdf4; color: #166534; }}
        .level-optimizing {{ color: var(--success); font-weight: 600; }}
        .level-managed {{ color: #0891b2; font-weight: 600; }}
        .level-defined {{ color: var(--warning); font-weight: 600; }}
        .level-developing {{ color: #ea580c; font-weight: 600; }}
        .level-initial {{ color: var(--danger); font-weight: 600; }}
        .progress-bar {{
            height: 8px;
            background: var(--gray-200);
            border-radius: 4px;
            overflow: hidden;
        }}
        .progress-bar .fill {{
            height: 100%;
            background: var(--primary);
            transition: width 0.3s;
        }}
        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--gray-700);
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            {company_header}
            <h1>{report.title}</h1>
            <p>Framework: {report.framework.upper()} | Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <h3>Overall Score</h3>
                <div class="value">{report.maturity.overall_score:.0f}%</div>
            </div>
            <div class="stat-card">
                <h3>Maturity Level</h3>
                <div class="value">{report.maturity.overall_level.name if report.maturity else 'N/A'}</div>
            </div>
            <div class="stat-card">
                <h3>Checks Passed</h3>
                <div class="value success">{passed_checks}</div>
            </div>
            <div class="stat-card">
                <h3>Checks Failed</h3>
                <div class="value danger">{failed_checks}</div>
            </div>
            <div class="stat-card">
                <h3>Pass Rate</h3>
                <div class="value">{pass_rate:.0f}%</div>
            </div>
            <div class="stat-card">
                <h3>Open Gaps</h3>
                <div class="value warning">{report.gaps.total_gaps if report.gaps else 0}</div>
            </div>
        </div>

        <section>
            <h2>Maturity by Category</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Category</th>
                        <th>Score</th>
                        <th>Level</th>
                        <th>Implementation</th>
                    </tr>
                </thead>
                <tbody>
                    {maturity_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Compliance Gaps</h2>
            <table>
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Severity</th>
                        <th>Issue</th>
                        <th>Resources</th>
                    </tr>
                </thead>
                <tbody>
                    {gap_rows if gap_rows else '<tr><td colspan="4">No gaps identified</td></tr>'}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Failed Checks</h2>
            <table>
                <thead>
                    <tr>
                        <th>Check ID</th>
                        <th>Title</th>
                        <th>Resource</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {failed_rows if failed_rows else '<tr><td colspan="4">All checks passed</td></tr>'}
                </tbody>
            </table>
        </section>

        <footer>
            <p>Generated by Attestful - OSCAL-First Compliance Platform</p>
            <p>Report ID: {report.id}</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def _build_markdown(self, report: ComplianceReport) -> str:
        """Build Markdown report content."""
        total_checks = len(report.check_results)
        passed_checks = sum(1 for r in report.check_results if r.passed)
        failed_checks = total_checks - passed_checks
        pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        md = f"""# {report.title}

**Framework:** {report.framework.upper()}
**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}
**Report ID:** {report.id}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Overall Score | {report.maturity.overall_score:.0f}% |
| Maturity Level | {report.maturity.overall_level.name if report.maturity else 'N/A'} |
| Checks Passed | {passed_checks} |
| Checks Failed | {failed_checks} |
| Pass Rate | {pass_rate:.0f}% |
| Open Gaps | {report.gaps.total_gaps if report.gaps else 0} |

---

## Maturity by Category

| ID | Category | Score | Level | Implementation |
|----|----------|-------|-------|----------------|
"""

        if report.maturity:
            for cat in report.maturity.category_scores:
                md += f"| {cat.category_id} | {cat.name} | {cat.score:.1f} | {cat.level.name} | {cat.implementation_rate:.0f}% |\n"

        md += """
---

## Compliance Gaps

| Control | Severity | Issue | Resources |
|---------|----------|-------|-----------|
"""

        if report.gaps:
            for gap in report.gaps.gaps[:20]:
                md += f"| {gap.control_id} | {gap.severity.value.upper()} | {gap.title} | {len(gap.affected_resources)} |\n"

        md += """
---

## Failed Checks

| Check ID | Title | Resource | Severity |
|----------|-------|----------|----------|
"""

        for result in report.check_results:
            if not result.passed:
                md += f"| {result.check.id} | {result.check.title} | {result.resource_id} | {result.check.severity.upper()} |\n"

        md += """
---

*Generated by Attestful - OSCAL-First Compliance Platform*
"""

        return md

    def _build_oscal_assessment_results(self, report: ComplianceReport) -> dict[str, Any]:
        """Build OSCAL Assessment Results document."""
        now = datetime.now(timezone.utc)

        # Build findings from check results
        findings = []
        for result in report.check_results:
            finding = {
                "uuid": str(uuid4()),
                "title": result.check.title,
                "description": result.check.description,
                "target": {
                    "type": "component",
                    "target-id": result.resource_id,
                    "status": {
                        "state": "satisfied" if result.passed else "not-satisfied",
                    },
                },
                "implementation-statement-uuid": str(uuid4()),
                "related-observations": [],
            }

            if not result.passed:
                finding["target"]["status"]["reason"] = "Check failed"

            findings.append(finding)

        # Build observations
        observations = []
        for result in report.check_results:
            obs = {
                "uuid": str(uuid4()),
                "title": f"Check: {result.check.title}",
                "description": result.check.description,
                "methods": ["AUTOMATED"],
                "types": ["finding"],
                "collected": result.evaluated_at.isoformat(),
                "subjects": [
                    {
                        "subject-uuid": str(uuid4()),
                        "type": "component",
                        "title": result.resource_id,
                    }
                ],
            }
            observations.append(obs)

        # Build the Assessment Results document
        oscal_ar = {
            "assessment-results": {
                "uuid": report.id,
                "metadata": {
                    "title": report.title,
                    "last-modified": now.isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                    "roles": [
                        {
                            "id": "assessor",
                            "title": "Assessor",
                        }
                    ],
                    "parties": [
                        {
                            "uuid": str(uuid4()),
                            "type": "tool",
                            "name": "Attestful",
                        }
                    ],
                },
                "import-ap": {
                    "href": "#",  # Would reference assessment plan
                },
                "results": [
                    {
                        "uuid": str(uuid4()),
                        "title": f"{report.framework.upper()} Assessment Results",
                        "description": f"Automated assessment results for {report.framework}",
                        "start": (report.period_start or now).isoformat(),
                        "end": (report.period_end or now).isoformat(),
                        "findings": findings,
                        "observations": observations,
                        "attestations": [
                            {
                                "responsible-parties": [
                                    {
                                        "role-id": "assessor",
                                        "party-uuids": [],
                                    }
                                ],
                                "parts": [
                                    {
                                        "name": "summary",
                                        "prose": f"Assessment completed with {sum(1 for r in report.check_results if r.passed)}/{len(report.check_results)} checks passing.",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        }

        return oscal_ar
