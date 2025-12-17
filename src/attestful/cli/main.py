"""
Main CLI entry point for Attestful.

Provides the `attestful` command with subcommands for scanning,
evidence collection, analysis, reporting, and OSCAL operations.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from attestful import __version__
from attestful.core.logging import setup_logging, get_logger

# Console for rich output
console = Console()
logger = get_logger("cli")


# =============================================================================
# Main CLI Group
# =============================================================================


@click.group()
@click.version_option(version=__version__, prog_name="attestful")
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug logging",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress non-error output",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format",
)
@click.pass_context
def cli(
    ctx: click.Context,
    debug: bool,
    quiet: bool,
    config: Path | None,
    output_format: str,
) -> None:
    """
    Attestful - OSCAL-first compliance automation platform.

    An open-source, self-hosted alternative to Vanta supporting
    NIST CSF 2.0, NIST 800-53, FedRAMP, SOC 2, ISO 27001, and HITRUST.
    """
    # Set up logging based on flags
    if debug:
        setup_logging(level="DEBUG")
    elif quiet:
        setup_logging(level="ERROR", quiet=True)
    else:
        setup_logging(level="INFO")

    # Store context for subcommands
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    ctx.obj["quiet"] = quiet
    ctx.obj["config"] = config
    ctx.obj["output_format"] = output_format


# =============================================================================
# Scan Commands
# =============================================================================


@cli.group()
@click.pass_context
def scan(ctx: click.Context) -> None:
    """Run compliance scans against cloud infrastructure."""
    pass


@scan.command("aws")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["soc2", "cis", "nist-800-53", "all"]),
    default="all",
    help="Compliance framework to check against",
)
@click.option(
    "--region",
    "-r",
    multiple=True,
    help="AWS regions to scan (can be specified multiple times)",
)
@click.option(
    "--profile",
    "-p",
    help="AWS profile name",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="info",
    help="Minimum severity to report",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for results (JSON)",
)
@click.pass_context
def scan_aws(
    ctx: click.Context,
    framework: str,
    region: tuple[str, ...],
    profile: str | None,
    severity: str,
    output: str | None,
) -> None:
    """Scan AWS infrastructure for compliance issues."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.cloud import AWSCollector, AWSCollectorConfig
    from attestful.core import create_default_evaluator

    console.print(f"[bold blue]Attestful AWS Scan[/bold blue]")
    console.print(f"  Framework: {framework}")
    console.print(f"  Regions: {', '.join(region) if region else 'all'}")
    console.print(f"  Profile: {profile or 'default'}")
    console.print(f"  Min Severity: {severity}")
    console.print()

    # Create collector
    config = AWSCollectorConfig(
        profile=profile,
        regions=list(region) if region else [],
    )
    collector = AWSCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating AWS credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate AWS credentials.[/red]")
            console.print("Run 'attestful configure credentials --platform aws' to set up credentials.")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect resources
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting AWS resources...", total=None)
        try:
            resources = collector.collect_resources()
            progress.update(task, description=f"[green]Collected {len(resources)} resources[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect resources: {e}[/red]")
            return

    if not resources:
        console.print("[yellow]No resources found to scan.[/yellow]")
        return

    # Show resource breakdown
    resource_counts: dict[str, int] = {}
    for r in resources:
        resource_counts[r.type] = resource_counts.get(r.type, 0) + 1

    console.print()
    console.print("[bold]Resources Found:[/bold]")
    for rtype, count in sorted(resource_counts.items()):
        console.print(f"  {rtype}: {count}")
    console.print()

    # Run compliance checks
    evaluator = create_default_evaluator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running compliance checks...", total=None)
        results = evaluator.evaluate(
            resources,
            severity=severity,
            framework=framework if framework != "all" else None,
        )
        progress.update(task, description=f"[green]Completed {len(results)} checks[/green]")

    # Summarize results
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    console.print()
    console.print("[bold]Scan Results:[/bold]")
    console.print(f"  [green]Passed:[/green] {passed}")
    console.print(f"  [red]Failed:[/red] {failed}")
    console.print(f"  Pass Rate: {(passed / len(results) * 100) if results else 0:.1f}%")
    console.print()

    # Show failed checks
    if failed > 0:
        failed_results = [r for r in results if not r.passed]

        # Group by severity
        by_severity: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for r in failed_results:
            sev = r.check.severity
            if sev in by_severity:
                by_severity[sev].append(r)

        console.print("[bold]Failed Checks:[/bold]")
        for sev in ["critical", "high", "medium", "low"]:
            if by_severity[sev]:
                color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}[sev]
                console.print(f"\n  [{color}]{sev.upper()}[/{color}] ({len(by_severity[sev])})")
                for r in by_severity[sev][:5]:  # Show top 5 per severity
                    console.print(f"    - {r.check.title}")
                    console.print(f"      Resource: {r.resource_id}")
                if len(by_severity[sev]) > 5:
                    console.print(f"    ... and {len(by_severity[sev]) - 5} more")

    # Save results if output specified
    if output:
        import json
        output_data = {
            "scan_type": "aws",
            "framework": framework,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_resources": len(resources),
                "total_checks": len(results),
                "passed": passed,
                "failed": failed,
            },
            "results": [
                {
                    "check_id": r.check.id,
                    "check_title": r.check.title,
                    "severity": r.check.severity,
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type,
                    "passed": r.passed,
                }
                for r in results
            ],
        }
        Path(output).write_text(json.dumps(output_data, indent=2))
        console.print(f"\n[dim]Results saved to {output}[/dim]")


@scan.command("soc2")
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["aws", "azure", "gcp", "all"]),
    default="aws",
    help="Cloud provider to scan",
)
@click.option(
    "--region",
    "-r",
    multiple=True,
    help="Regions to scan (can be specified multiple times)",
)
@click.option(
    "--profile",
    help="AWS profile name (for AWS provider)",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="info",
    help="Minimum severity to report",
)
@click.option(
    "--control",
    "-c",
    multiple=True,
    help="Specific controls to check (e.g., CC6.1, CC7.2)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for results (JSON)",
)
@click.option(
    "--generate-oscal",
    is_flag=True,
    help="Also generate OSCAL Assessment Results",
)
@click.pass_context
def scan_soc2(
    ctx: click.Context,
    provider: str,
    region: tuple[str, ...],
    profile: str | None,
    severity: str,
    control: tuple[str, ...],
    output: str | None,
    generate_oscal: bool,
) -> None:
    """Run SOC 2 Type II compliance scan.

    Scans cloud infrastructure against SOC 2 Trust Services Criteria controls
    including CC6 (Access), CC7 (Operations), CC8 (Change Management), and
    CC9 (Risk Mitigation).

    Examples:

        attestful scan soc2 --provider aws

        attestful scan soc2 --provider aws --severity high

        attestful scan soc2 --provider aws --control CC6.1 --control CC7.2

        attestful scan soc2 --provider aws -o results.json --generate-oscal
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.cloud import AWSCollector, AWSCollectorConfig
    from attestful.frameworks import create_soc2_evaluator, get_soc2_framework, SOC2_CONTROLS

    console.print(f"[bold blue]Attestful SOC 2 Type II Compliance Scan[/bold blue]")
    console.print(f"  Provider: {provider}")
    console.print(f"  Regions: {', '.join(region) if region else 'all'}")
    console.print(f"  Min Severity: {severity}")
    if control:
        console.print(f"  Controls: {', '.join(control)}")
    console.print()

    # Currently only AWS is supported
    if provider != "aws":
        console.print(f"[yellow]Provider '{provider}' not yet supported. Using AWS.[/yellow]")
        provider = "aws"

    # Create collector
    config = AWSCollectorConfig(
        profile=profile,
        regions=list(region) if region else [],
    )
    collector = AWSCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate AWS credentials.[/red]")
            console.print("Run 'attestful configure credentials --platform aws' to set up credentials.")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect resources
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting resources...", total=None)
        try:
            resources = collector.collect_resources()
            progress.update(task, description=f"[green]Collected {len(resources)} resources[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect resources: {e}[/red]")
            return

    if not resources:
        console.print("[yellow]No resources found to scan.[/yellow]")
        return

    # Show resource breakdown
    resource_counts: dict[str, int] = {}
    for r in resources:
        resource_counts[r.type] = resource_counts.get(r.type, 0) + 1

    console.print()
    console.print("[bold]Resources Found:[/bold]")
    for rtype, count in sorted(resource_counts.items()):
        console.print(f"  {rtype}: {count}")
    console.print()

    # Create SOC 2 evaluator
    evaluator = create_soc2_evaluator()

    # Get checks for specific controls if requested
    check_ids: list[str] | None = None
    if control:
        framework = get_soc2_framework()
        check_ids = []
        for ctrl in control:
            ctrl_checks = framework.get_checks_for_control(ctrl)
            check_ids.extend(ctrl_checks)
        if not check_ids:
            console.print(f"[yellow]No checks found for controls: {', '.join(control)}[/yellow]")
            return

    # Run compliance checks
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running SOC 2 compliance checks...", total=None)
        results = evaluator.evaluate(
            resources,
            check_ids=check_ids,
            severity=severity,
        )
        progress.update(task, description=f"[green]Completed {len(results)} checks[/green]")

    # Summarize results
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    console.print()
    console.print("[bold]SOC 2 Scan Results:[/bold]")
    console.print(f"  [green]Passed:[/green] {passed}")
    console.print(f"  [red]Failed:[/red] {failed}")
    console.print(f"  Pass Rate: {(passed / len(results) * 100) if results else 0:.1f}%")
    console.print()

    # Group failures by control
    if failed > 0:
        failed_results = [r for r in results if not r.passed]

        # Group by SOC 2 control
        by_control: dict[str, list] = {}
        for r in failed_results:
            soc2_controls = r.check.framework_mappings.get("soc2", []) if r.check.framework_mappings else []
            for ctrl in soc2_controls:
                if ctrl not in by_control:
                    by_control[ctrl] = []
                by_control[ctrl].append(r)

        console.print("[bold]Failed Checks by SOC 2 Control:[/bold]")
        for ctrl in sorted(by_control.keys()):
            ctrl_results = by_control[ctrl]
            ctrl_info = SOC2_CONTROLS.get(ctrl)
            ctrl_title = ctrl_info.title if ctrl_info else ctrl

            console.print(f"\n  [cyan]{ctrl}[/cyan]: {ctrl_title}")
            console.print(f"    Failures: {len(ctrl_results)}")

            # Group by severity within control
            by_severity: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
            for r in ctrl_results:
                sev = r.check.severity
                if sev in by_severity:
                    by_severity[sev].append(r)

            for sev in ["critical", "high", "medium", "low"]:
                if by_severity[sev]:
                    color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue"}[sev]
                    console.print(f"    [{color}]{sev.upper()}[/{color}]: {len(by_severity[sev])}")
                    for r in by_severity[sev][:3]:
                        console.print(f"      - {r.check.title}")
                    if len(by_severity[sev]) > 3:
                        console.print(f"      ... and {len(by_severity[sev]) - 3} more")

    # Save results if output specified
    if output:
        import json
        output_data = {
            "scan_type": "soc2",
            "framework": "soc2",
            "provider": provider,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_resources": len(resources),
                "total_checks": len(results),
                "passed": passed,
                "failed": failed,
                "pass_rate": (passed / len(results) * 100) if results else 0,
            },
            "results": [
                {
                    "check_id": r.check.id,
                    "check_title": r.check.title,
                    "severity": r.check.severity,
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type,
                    "passed": r.passed,
                    "soc2_controls": r.check.framework_mappings.get("soc2", []) if r.check.framework_mappings else [],
                }
                for r in results
            ],
        }
        Path(output).write_text(json.dumps(output_data, indent=2))
        console.print(f"\n[dim]Results saved to {output}[/dim]")

        # Generate OSCAL if requested
        if generate_oscal:
            from attestful.oscal.assessment import AssessmentResultsGenerator, AssessmentConfig
            from attestful.core.models import CheckResult, Severity, CheckStatus

            console.print()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Generating OSCAL Assessment Results...", total=None)

                # Convert to proper CheckResult format
                check_results = []
                for r in results:
                    severity_str = r.check.severity.lower()
                    severity_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                        "info": Severity.INFO,
                    }
                    sev = severity_map.get(severity_str, Severity.MEDIUM)

                    check_results.append(CheckResult(
                        check=r.check,
                        check_id=r.check.id,
                        resource_id=r.resource_id,
                        resource_type=r.resource_type,
                        passed=r.passed,
                        status=CheckStatus.PASS if r.passed else CheckStatus.FAIL,
                        severity=sev,
                        evaluated_at=datetime.now(timezone.utc),
                    ))

                oscal_config = AssessmentConfig(
                    title="SOC 2 Type II Compliance Assessment",
                    description="Automated SOC 2 Trust Services Criteria compliance assessment",
                    organization_name="Organization",
                )

                generator = AssessmentResultsGenerator(oscal_config)
                generator.add_check_results(check_results)

                oscal_output = output.rsplit(".", 1)[0] + "_oscal.json"
                generator.save(Path(oscal_output), format="json")
                progress.update(task, description="[green]OSCAL Assessment Results generated[/green]")

            console.print(f"[dim]OSCAL Assessment Results saved to {oscal_output}[/dim]")


@scan.command("list")
@click.option("--limit", "-n", default=10, help="Number of scans to show")
@click.pass_context
def scan_list(ctx: click.Context, limit: int) -> None:
    """List recent scans."""
    console.print("[bold]Recent Scans[/bold]")
    console.print("[dim]No scans found. Run 'attestful scan aws' to start.[/dim]")


# =============================================================================
# Collect Commands
# =============================================================================


@cli.group()
@click.pass_context
def collect(ctx: click.Context) -> None:
    """Collect evidence from platforms."""
    pass


@collect.command("okta")
@click.option("--since", help="Collect evidence since this date (YYYY-MM-DD)")
@click.option(
    "--types",
    "-t",
    multiple=True,
    help="Evidence types to collect (users, mfa_factors, groups, applications, policies, system_log)",
)
@click.option("--output", "-o", type=click.Path(), help="Output directory for evidence")
@click.pass_context
def collect_okta(
    ctx: click.Context,
    since: str | None,
    types: tuple[str, ...],
    output: str | None,
) -> None:
    """Collect evidence from Okta."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.platforms import OktaCollector, OktaCollectorConfig
    from attestful.config import get_credential_store, get_settings
    from attestful.storage import EvidenceStore

    console.print("[bold blue]Collecting Okta Evidence[/bold blue]")

    # Get credentials
    store = get_credential_store()
    cred = store.get_default("okta")

    if not cred:
        console.print("[red]No Okta credentials configured.[/red]")
        console.print("Run 'attestful configure credentials --platform okta' to set up credentials.")
        return

    console.print(f"  Domain: {cred.data.get('domain')}")
    console.print()

    # Create collector
    config = OktaCollectorConfig(
        domain=cred.data.get("domain", ""),
        api_token=cred.data.get("api_token", ""),
    )
    collector = OktaCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Okta credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate Okta credentials.[/red]")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Okta evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence:
        console.print(f"  - {evidence.evidence_type}")

    if result.errors:
        console.print()
        console.print("[yellow]Errors:[/yellow]")
        for error in result.errors:
            console.print(f"  - {error}")

    # Store evidence
    settings = get_settings()
    evidence_dir = Path(output) if output else settings.effective_evidence_dir
    evidence_store = EvidenceStore(evidence_dir)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Storing evidence...", total=None)
        stored = evidence_store.store_collection_result(result)
        progress.update(task, description=f"[green]Stored {len(stored)} evidence items[/green]")

    console.print()
    console.print(f"[dim]Evidence stored in {evidence_dir}[/dim]")


@collect.command("aws")
@click.option(
    "--types",
    "-t",
    multiple=True,
    help="Evidence types to collect",
)
@click.option("--output", "-o", type=click.Path(), help="Output directory for evidence")
@click.pass_context
def collect_aws(
    ctx: click.Context,
    types: tuple[str, ...],
    output: str | None,
) -> None:
    """Collect evidence from AWS."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.cloud import AWSCollector, AWSCollectorConfig
    from attestful.config import get_settings
    from attestful.storage import EvidenceStore

    console.print("[bold blue]Collecting AWS Evidence[/bold blue]")
    console.print()

    # Create collector
    config = AWSCollectorConfig()
    collector = AWSCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating AWS credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate AWS credentials.[/red]")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting AWS evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence:
        console.print(f"  - {evidence.evidence_type}")

    # Store evidence
    settings = get_settings()
    evidence_dir = Path(output) if output else settings.effective_evidence_dir
    evidence_store = EvidenceStore(evidence_dir)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Storing evidence...", total=None)
        stored = evidence_store.store_collection_result(result)
        progress.update(task, description=f"[green]Stored {len(stored)} evidence items[/green]")

    console.print()
    console.print(f"[dim]Evidence stored in {evidence_dir}[/dim]")


@collect.command("github")
@click.option("--organization", "-o", help="GitHub organization name")
@click.option(
    "--types",
    "-t",
    multiple=True,
    help="Evidence types to collect (repositories, branch_protection, security_alerts, collaborators, commits, pull_requests, workflows, audit_log)",
)
@click.option("--output", type=click.Path(), help="Output directory for evidence")
@click.option("--days", default=90, help="Number of days of history to collect")
@click.pass_context
def collect_github(
    ctx: click.Context,
    organization: str | None,
    types: tuple[str, ...],
    output: str | None,
    days: int,
) -> None:
    """Collect evidence from GitHub."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.platforms import GitHubCollector, GitHubCollectorConfig
    from attestful.config import get_credential_store, get_settings
    from attestful.storage import EvidenceStore

    console.print("[bold blue]Collecting GitHub Evidence[/bold blue]")

    # Get credentials
    store = get_credential_store()
    cred = store.get_default("github")

    if not cred:
        console.print("[red]No GitHub credentials configured.[/red]")
        console.print("Run 'attestful configure credentials --platform github' to set up credentials.")
        return

    org = organization or cred.data.get("organization", "")
    console.print(f"  Organization: {org or '(personal repos)'}")
    console.print()

    # Create collector
    config = GitHubCollectorConfig(
        token=cred.data.get("token", ""),
        organization=org,
        days_of_history=days,
    )
    collector = GitHubCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating GitHub credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate GitHub credentials.[/red]")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting GitHub evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence:
        console.print(f"  - {evidence.evidence_type}")

    if result.errors:
        console.print()
        console.print("[yellow]Errors:[/yellow]")
        for error in result.errors:
            console.print(f"  - {error}")

    # Store evidence
    settings = get_settings()
    evidence_dir = Path(output) if output else settings.effective_evidence_dir
    evidence_store = EvidenceStore(evidence_dir)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Storing evidence...", total=None)
        stored = evidence_store.store_collection_result(result)
        progress.update(task, description=f"[green]Stored {len(stored)} evidence items[/green]")

    console.print()
    console.print(f"[dim]Evidence stored in {evidence_dir}[/dim]")


@collect.command("list")
@click.pass_context
def collect_list(ctx: click.Context) -> None:
    """List available collectors."""
    table = Table(title="Available Collectors")
    table.add_column("Platform", style="cyan")
    table.add_column("Mode", style="green")
    table.add_column("Status", style="yellow")

    collectors = [
        ("aws", "Both", "[green]Available[/green]"),
        ("okta", "Evidence", "[green]Available[/green]"),
        ("github", "Both", "[green]Available[/green]"),
        ("azure", "Both", "[dim]Coming Soon[/dim]"),
        ("gcp", "Both", "[dim]Coming Soon[/dim]"),
        ("kubernetes", "Resource", "[dim]Coming Soon[/dim]"),
        ("gitlab", "Evidence", "[dim]Coming Soon[/dim]"),
        ("jira", "Evidence", "[dim]Coming Soon[/dim]"),
        ("jamf", "Evidence", "[dim]Coming Soon[/dim]"),
        ("google-workspace", "Evidence", "[dim]Coming Soon[/dim]"),
        ("snowflake", "Evidence", "[dim]Coming Soon[/dim]"),
        ("datadog", "Evidence", "[dim]Coming Soon[/dim]"),
        ("pagerduty", "Evidence", "[dim]Coming Soon[/dim]"),
        ("slack", "Evidence", "[dim]Coming Soon[/dim]"),
    ]

    for platform, mode, status in collectors:
        table.add_row(platform, mode, status)

    console.print(table)
    console.print()
    console.print("[dim]Mode: Both = Resources + Evidence, Resource = Compliance checks, Evidence = Audit documentation[/dim]")


# =============================================================================
# Analyze Commands
# =============================================================================


@cli.group()
@click.pass_context
def analyze(ctx: click.Context) -> None:
    """Analyze compliance posture and maturity."""
    pass


@analyze.command("maturity")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["nist-csf", "nist-800-53", "soc2", "iso27001", "hitrust"]),
    default="nist-csf",
    help="Framework to analyze",
)
@click.pass_context
def analyze_maturity(ctx: click.Context, framework: str) -> None:
    """Calculate maturity scores."""
    console.print(f"[bold blue]Maturity Analysis: {framework.upper()}[/bold blue]")
    console.print("[dim]No evidence collected yet. Run 'attestful collect' first.[/dim]")


@analyze.command("gaps")
@click.option("--framework", "-f", required=True, help="Target framework")
@click.pass_context
def analyze_gaps(ctx: click.Context, framework: str) -> None:
    """Identify compliance gaps."""
    console.print(f"[bold blue]Gap Analysis: {framework}[/bold blue]")
    console.print("[dim]No data available. Run scans and collect evidence first.[/dim]")


# =============================================================================
# Report Commands
# =============================================================================


@cli.group()
@click.pass_context
def report(ctx: click.Context) -> None:
    """Generate compliance reports."""
    pass


@report.command("generate")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["html", "json", "oscal", "markdown"]),
    default="html",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--framework",
    type=click.Choice(["nist-csf-2", "soc2", "nist-800-53"]),
    default="soc2",
    help="Framework to report on",
)
@click.option("--title", default="Compliance Assessment Report", help="Report title")
@click.option("--scan-file", type=click.Path(exists=True), help="JSON file from previous scan")
@click.pass_context
def report_generate(
    ctx: click.Context,
    fmt: str,
    output: str | None,
    framework: str,
    title: str,
    scan_file: str | None,
) -> None:
    """Generate a compliance report."""
    import json as json_module
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.reports import ReportGenerator, ReportFormat, ComplianceReport
    from attestful.analysis import MaturityCalculator, GapAnalyzer
    from attestful.core.models import CheckResult, ComplianceCheck

    console.print(f"[bold blue]Generating {fmt.upper()} Report[/bold blue]")
    console.print(f"  Framework: {framework}")
    console.print()

    # Load scan results if provided
    check_results: list[CheckResult] = []

    if scan_file:
        console.print(f"Loading scan results from {scan_file}...")
        try:
            scan_data = json_module.loads(Path(scan_file).read_text())
            for r in scan_data.get("results", []):
                check_results.append(CheckResult(
                    check=ComplianceCheck(
                        id=r["check_id"],
                        title=r["check_title"],
                        description="",
                        severity=r["severity"],
                    ),
                    resource_id=r["resource_id"],
                    resource_type=r["resource_type"],
                    passed=r["passed"],
                    evaluated_at=datetime.now(timezone.utc),
                ))
            console.print(f"  Loaded {len(check_results)} check results")
        except Exception as e:
            console.print(f"[red]Failed to load scan file: {e}[/red]")
            return

    # Calculate maturity
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Calculating maturity scores...", total=None)

        calculator = MaturityCalculator(framework=framework if framework in ["nist-csf-2"] else "nist-csf-2")
        calculator.add_check_results(check_results)
        maturity = calculator.calculate()

        progress.update(task, description=f"[green]Maturity: {maturity.overall_score:.0f}% ({maturity.overall_level.name})[/green]")

    # Run gap analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing compliance gaps...", total=None)

        analyzer = GapAnalyzer(framework=framework if framework in ["soc2"] else "soc2")
        analyzer.add_check_results(check_results)
        gaps = analyzer.analyze()

        progress.update(task, description=f"[green]Found {gaps.total_gaps} gaps[/green]")

    # Create report
    report = ComplianceReport(
        title=title,
        framework=framework,
        maturity=maturity,
        gaps=gaps,
        check_results=check_results,
    )

    # Determine output path
    if not output:
        ext = {"html": "html", "json": "json", "oscal": "json", "markdown": "md"}[fmt]
        output = f"attestful_report_{framework}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

    output_path = Path(output)

    # Generate report
    format_map = {
        "html": ReportFormat.HTML,
        "json": ReportFormat.JSON,
        "oscal": ReportFormat.OSCAL,
        "markdown": ReportFormat.MARKDOWN,
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Generating {fmt.upper()} report...", total=None)

        generator = ReportGenerator()
        result_path = generator.generate(report, output_path, format=format_map[fmt])

        progress.update(task, description="[green]Report generated[/green]")

    console.print()
    console.print(f"[bold green]Report saved to:[/bold green] {result_path}")

    # Show summary
    console.print()
    console.print("[bold]Report Summary:[/bold]")
    console.print(f"  Overall Score: {maturity.overall_score:.0f}%")
    console.print(f"  Maturity Level: {maturity.overall_level.name}")
    console.print(f"  Total Checks: {len(check_results)}")
    console.print(f"  Passed: {sum(1 for r in check_results if r.passed)}")
    console.print(f"  Failed: {sum(1 for r in check_results if not r.passed)}")
    console.print(f"  Compliance Gaps: {gaps.total_gaps}")


# =============================================================================
# OSCAL Commands
# =============================================================================


@cli.group()
@click.pass_context
def oscal(ctx: click.Context) -> None:
    """OSCAL document operations."""
    pass


@oscal.group()
@click.pass_context
def catalog(ctx: click.Context) -> None:
    """Catalog operations."""
    pass


@catalog.command("list")
@click.pass_context
def catalog_list(ctx: click.Context) -> None:
    """List available OSCAL catalogs."""
    table = Table(title="Available Catalogs")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Controls", style="green")

    catalogs = [
        ("nist-800-53-rev5", "NIST SP 800-53 Rev 5", "1000+"),
        ("nist-csf-2.0", "NIST Cybersecurity Framework 2.0", "106"),
        ("soc2-tsc", "SOC 2 Trust Services Criteria", "64"),
    ]

    for cat_id, title, controls in catalogs:
        table.add_row(cat_id, title, controls)

    console.print(table)


@oscal.group()
@click.pass_context
def ssp(ctx: click.Context) -> None:
    """System Security Plan operations."""
    pass


@ssp.command("generate")
@click.option("--profile", "-p", required=True, help="OSCAL profile to use (e.g., nist-800-53-moderate)")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--system-name", "-n", required=True, help="Name of the system")
@click.option("--system-id", "-i", required=True, help="Unique identifier for the system")
@click.option("--description", "-d", required=True, help="System description")
@click.option("--scan-file", type=click.Path(exists=True), help="JSON file from previous scan")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Output format",
)
@click.pass_context
def ssp_generate(
    ctx: click.Context,
    profile: str,
    output: str | None,
    system_name: str,
    system_id: str,
    description: str,
    scan_file: str | None,
    fmt: str,
) -> None:
    """Generate an OSCAL System Security Plan."""
    import json as json_module
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.oscal.ssp import SSPGenerator, SystemConfig, ComponentConfig
    from attestful.core.models import CheckResult, ComplianceCheck

    console.print(f"[bold blue]Generating OSCAL System Security Plan[/bold blue]")
    console.print(f"  System Name: {system_name}")
    console.print(f"  System ID: {system_id}")
    console.print(f"  Profile: {profile}")
    console.print()

    # Create system config
    config = SystemConfig(
        system_name=system_name,
        system_id=system_id,
        description=description,
    )

    # Create SSP generator
    generator = SSPGenerator(config, profile_href=f"#{profile}")

    # Add a default component
    generator.add_component(ComponentConfig(
        title="Primary Application",
        description="Main application component",
        type="software",
    ))

    # Load check results from scan file if provided
    if scan_file:
        console.print(f"Loading scan results from {scan_file}...")
        try:
            scan_data = json_module.loads(Path(scan_file).read_text())
            check_results: list[CheckResult] = []

            for r in scan_data.get("results", []):
                check_results.append(CheckResult(
                    check=ComplianceCheck(
                        id=r["check_id"],
                        title=r["check_title"],
                        description="",
                        severity=r["severity"],
                        framework_mappings={"soc2": [r["check_id"]]} if "CC" in r["check_id"] else {},
                    ),
                    resource_id=r["resource_id"],
                    resource_type=r["resource_type"],
                    passed=r["passed"],
                    evaluated_at=datetime.now(timezone.utc),
                ))

            generator.add_check_results(check_results)
            console.print(f"  Loaded {len(check_results)} check results")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to load scan file: {e}[/yellow]")

    # Determine output path
    if not output:
        ext = "json" if fmt == "json" else "yaml"
        output = f"ssp_{system_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

    output_path = Path(output)

    # Generate SSP
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating SSP...", total=None)
        result_path = generator.save(output_path, format=fmt)
        progress.update(task, description="[green]SSP generated[/green]")

    console.print()
    console.print(f"[bold green]SSP saved to:[/bold green] {result_path}")
    console.print()
    console.print("[bold]SSP Contents:[/bold]")
    console.print(f"  Components: {len(generator.components)}")
    console.print(f"  Users: {len(generator.users) if generator.users else 1} (default)")
    console.print(f"  Control Implementations: {len(generator.control_implementations)}")


@oscal.group()
@click.pass_context
def assessment(ctx: click.Context) -> None:
    """Assessment Results operations."""
    pass


@assessment.command("generate")
@click.option("--title", "-t", required=True, help="Assessment title")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--scan-file", type=click.Path(exists=True), required=True, help="JSON file from previous scan")
@click.option("--description", "-d", default="Automated compliance assessment", help="Assessment description")
@click.option("--organization", default="Organization", help="Organization name")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Output format",
)
@click.pass_context
def assessment_generate(
    ctx: click.Context,
    title: str,
    output: str | None,
    scan_file: str,
    description: str,
    organization: str,
    fmt: str,
) -> None:
    """Generate OSCAL Assessment Results from scan results."""
    import json as json_module
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.oscal.assessment import AssessmentResultsGenerator, AssessmentConfig, get_assessment_summary
    from attestful.core.models import CheckResult, ComplianceCheck, Severity, CheckStatus

    console.print(f"[bold blue]Generating OSCAL Assessment Results[/bold blue]")
    console.print(f"  Title: {title}")
    console.print(f"  Organization: {organization}")
    console.print()

    # Load scan results
    console.print(f"Loading scan results from {scan_file}...")
    try:
        scan_data = json_module.loads(Path(scan_file).read_text())
        check_results: list[CheckResult] = []

        for r in scan_data.get("results", []):
            severity_str = r.get("severity", "medium").lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            check_results.append(CheckResult(
                check=ComplianceCheck(
                    id=r["check_id"],
                    title=r["check_title"],
                    description="",
                    severity=r["severity"],
                    framework_mappings={"soc2": [r["check_id"]]} if "CC" in r["check_id"] else {},
                ),
                check_id=r["check_id"],
                resource_id=r["resource_id"],
                resource_type=r["resource_type"],
                passed=r["passed"],
                status=CheckStatus.PASS if r["passed"] else CheckStatus.FAIL,
                severity=severity,
                evaluated_at=datetime.now(timezone.utc),
            ))

        console.print(f"  Loaded {len(check_results)} check results")
    except Exception as e:
        console.print(f"[red]Failed to load scan file: {e}[/red]")
        return

    # Create config and generator
    config = AssessmentConfig(
        title=title,
        description=description,
        organization_name=organization,
    )

    generator = AssessmentResultsGenerator(config)
    generator.add_check_results(check_results)

    # Determine output path
    if not output:
        ext = "json" if fmt == "json" else "yaml"
        output = f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

    output_path = Path(output)

    # Generate Assessment Results
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating Assessment Results...", total=None)
        result_path = generator.save(output_path, format=fmt)
        progress.update(task, description="[green]Assessment Results generated[/green]")

    # Get summary
    results = generator.generate()
    summary = get_assessment_summary(results)

    console.print()
    console.print(f"[bold green]Assessment Results saved to:[/bold green] {result_path}")
    console.print()
    console.print("[bold]Assessment Summary:[/bold]")
    console.print(f"  Total Checks: {summary['passed_checks'] + summary['failed_checks']}")
    console.print(f"  [green]Passed:[/green] {summary['passed_checks']}")
    console.print(f"  [red]Failed:[/red] {summary['failed_checks']}")
    console.print(f"  Pass Rate: {summary['pass_rate']:.1f}%")
    console.print(f"  Observations: {summary['total_observations']}")
    console.print(f"  Findings: {summary['total_findings']}")


@assessment.command("summary")
@click.argument("assessment_file", type=click.Path(exists=True))
@click.pass_context
def assessment_summary(ctx: click.Context, assessment_file: str) -> None:
    """Display summary of an OSCAL Assessment Results file."""
    from attestful.oscal.assessment import AssessmentResultsLoader, get_assessment_summary

    console.print(f"[bold blue]Assessment Results Summary[/bold blue]")
    console.print()

    loader = AssessmentResultsLoader()
    try:
        results = loader.load(assessment_file)
        summary = get_assessment_summary(results)

        console.print(f"[bold]Title:[/bold] {summary['title']}")
        console.print(f"[bold]Date:[/bold] {summary['assessment_date']}")
        console.print(f"[bold]Status:[/bold] {summary['status']}")
        console.print()
        console.print("[bold]Results:[/bold]")
        console.print(f"  Total Checks: {summary['passed_checks'] + summary['failed_checks']}")
        console.print(f"  [green]Passed:[/green] {summary['passed_checks']}")
        console.print(f"  [red]Failed:[/red] {summary['failed_checks']}")
        console.print(f"  Pass Rate: {summary['pass_rate']:.1f}%")
        console.print()
        console.print(f"  Observations: {summary['total_observations']}")
        console.print(f"  Findings: {summary['total_findings']}")

    except Exception as e:
        console.print(f"[red]Failed to load assessment file: {e}[/red]")


# =============================================================================
# Frameworks Commands
# =============================================================================


@cli.group()
@click.pass_context
def frameworks(ctx: click.Context) -> None:
    """View and manage compliance frameworks."""
    pass


@frameworks.command("list")
@click.pass_context
def frameworks_list(ctx: click.Context) -> None:
    """List available compliance frameworks."""
    table = Table(title="Available Compliance Frameworks")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Controls", style="green")
    table.add_column("Checks", style="yellow")
    table.add_column("Status", style="magenta")

    frameworks_data = [
        ("soc2", "SOC 2 Type II Trust Services Criteria", "15", "35+", "[green]Available[/green]"),
        ("nist-800-53", "NIST SP 800-53 Rev 5", "1000+", "20", "[green]Available[/green]"),
        ("nist-csf-2", "NIST Cybersecurity Framework 2.0", "106", "0", "[yellow]Partial[/yellow]"),
        ("cis-aws", "CIS AWS Foundations Benchmark", "60", "20", "[green]Available[/green]"),
        ("iso-27001", "ISO 27001:2022", "93", "0", "[dim]Coming Soon[/dim]"),
        ("hitrust", "HITRUST CSF", "500+", "0", "[dim]Coming Soon[/dim]"),
        ("fedramp", "FedRAMP (Moderate)", "325", "0", "[dim]Coming Soon[/dim]"),
        ("pci-dss", "PCI DSS 4.0", "280", "0", "[dim]Coming Soon[/dim]"),
    ]

    for fid, name, controls, checks, status in frameworks_data:
        table.add_row(fid, name, controls, checks, status)

    console.print(table)
    console.print()
    console.print("[dim]Use 'attestful frameworks show <id>' to view framework details.[/dim]")


@frameworks.command("show")
@click.argument("framework_id")
@click.option("--controls", "-c", is_flag=True, help="Show all controls")
@click.option("--checks", is_flag=True, help="Show mapped checks")
@click.pass_context
def frameworks_show(ctx: click.Context, framework_id: str, controls: bool, checks: bool) -> None:
    """Show details for a specific framework."""
    if framework_id.lower() == "soc2":
        from attestful.frameworks import (
            get_soc2_framework,
            get_soc2_aws_checks,
            SOC2_CONTROLS,
            TSC_SECURITY,
            TSC_AVAILABILITY,
        )

        framework = get_soc2_framework()
        aws_checks = get_soc2_aws_checks()

        console.print("[bold blue]SOC 2 Type II Trust Services Criteria[/bold blue]")
        console.print(f"  Version: {framework.version}")
        console.print(f"  Total Controls: {len(framework.controls)}")
        console.print(f"  Automated Checks: {len(aws_checks)}")
        console.print()

        # Control categories
        security_controls = [c for c in framework.controls.values() if c.category == TSC_SECURITY]
        availability_controls = [c for c in framework.controls.values() if c.category == TSC_AVAILABILITY]

        console.print("[bold]Control Categories:[/bold]")
        console.print(f"  Security (Common Criteria): {len(security_controls)} controls")
        console.print(f"  Availability: {len(availability_controls)} controls")
        console.print()

        # Control groups
        console.print("[bold]Security Control Groups:[/bold]")
        groups = {
            "CC6": "Logical and Physical Access Controls",
            "CC7": "System Operations",
            "CC8": "Change Management",
            "CC9": "Risk Mitigation",
        }
        for prefix, description in groups.items():
            group_controls = [c for c in security_controls if c.id.startswith(prefix)]
            group_checks = sum(
                len(framework.get_checks_for_control(c.id)) for c in group_controls
            )
            console.print(f"  {prefix}: {description}")
            console.print(f"       Controls: {len(group_controls)}, Mapped Checks: {group_checks}")

        if controls:
            console.print()
            console.print("[bold]All Controls:[/bold]")
            for ctrl_id in sorted(SOC2_CONTROLS.keys()):
                ctrl = SOC2_CONTROLS[ctrl_id]
                check_count = len(framework.get_checks_for_control(ctrl_id))
                console.print(f"\n  [cyan]{ctrl_id}[/cyan]: {ctrl.title}")
                console.print(f"    Category: {ctrl.category}")
                console.print(f"    Checks: {check_count}")
                if ctrl.points_of_focus:
                    console.print(f"    Points of Focus: {len(ctrl.points_of_focus)}")

        if checks:
            console.print()
            console.print("[bold]Automated Checks:[/bold]")

            # Group by severity
            by_severity: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for check in aws_checks:
                by_severity[check.severity].append(check)

            for severity in ["critical", "high", "medium", "low", "info"]:
                if by_severity[severity]:
                    color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}[severity]
                    console.print(f"\n  [{color}]{severity.upper()}[/{color}] ({len(by_severity[severity])} checks)")
                    for check in by_severity[severity]:
                        soc2_ctrl = ", ".join(check.frameworks.get("soc2", []))
                        console.print(f"    {check.id}")
                        console.print(f"      {check.title}")
                        console.print(f"      Controls: {soc2_ctrl}")

    elif framework_id.lower() in ["nist-800-53", "cis-aws"]:
        console.print(f"[bold blue]{framework_id.upper()}[/bold blue]")
        console.print()
        console.print("[dim]Basic support available. Use 'attestful scan aws --framework {framework_id}' to run checks.[/dim]")
    else:
        console.print(f"[yellow]Framework '{framework_id}' not found or not yet implemented.[/yellow]")
        console.print("Run 'attestful frameworks list' to see available frameworks.")


@frameworks.command("controls")
@click.argument("framework_id")
@click.option("--search", "-s", help="Search controls by keyword")
@click.option("--category", "-c", help="Filter by category")
@click.pass_context
def frameworks_controls(
    ctx: click.Context,
    framework_id: str,
    search: str | None,
    category: str | None,
) -> None:
    """List controls for a specific framework."""
    if framework_id.lower() == "soc2":
        from attestful.frameworks import SOC2_CONTROLS, get_soc2_framework

        framework = get_soc2_framework()
        controls_list = list(SOC2_CONTROLS.values())

        # Filter by category
        if category:
            controls_list = [c for c in controls_list if category.lower() in c.category.lower()]

        # Filter by search
        if search:
            search_lower = search.lower()
            controls_list = [
                c for c in controls_list
                if search_lower in c.id.lower()
                or search_lower in c.title.lower()
                or search_lower in c.description.lower()
            ]

        if not controls_list:
            console.print("[yellow]No controls found matching your criteria.[/yellow]")
            return

        table = Table(title=f"SOC 2 Controls ({len(controls_list)} results)")
        table.add_column("ID", style="cyan", width=8)
        table.add_column("Title", style="white", width=45)
        table.add_column("Category", style="green", width=12)
        table.add_column("Checks", style="yellow", width=8)

        for ctrl in sorted(controls_list, key=lambda c: c.id):
            check_count = len(framework.get_checks_for_control(ctrl.id))
            table.add_row(
                ctrl.id,
                ctrl.title[:43] + "..." if len(ctrl.title) > 45 else ctrl.title,
                ctrl.category,
                str(check_count),
            )

        console.print(table)
    else:
        console.print(f"[yellow]Framework '{framework_id}' not found or not yet implemented.[/yellow]")


@frameworks.command("checks")
@click.argument("framework_id")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]), help="Filter by severity")
@click.option("--resource-type", "-r", help="Filter by resource type")
@click.option("--control", "-c", help="Filter by control ID")
@click.pass_context
def frameworks_checks(
    ctx: click.Context,
    framework_id: str,
    severity: str | None,
    resource_type: str | None,
    control: str | None,
) -> None:
    """List compliance checks for a specific framework."""
    if framework_id.lower() == "soc2":
        from attestful.frameworks import get_soc2_aws_checks, get_soc2_framework

        framework = get_soc2_framework()
        checks_list = get_soc2_aws_checks()

        # Filter by severity
        if severity:
            checks_list = [c for c in checks_list if c.severity == severity]

        # Filter by resource type
        if resource_type:
            checks_list = [c for c in checks_list if resource_type in c.resource_types]

        # Filter by control
        if control:
            control_checks = set(framework.get_checks_for_control(control))
            checks_list = [c for c in checks_list if c.id in control_checks]

        if not checks_list:
            console.print("[yellow]No checks found matching your criteria.[/yellow]")
            return

        table = Table(title=f"SOC 2 Checks ({len(checks_list)} results)")
        table.add_column("ID", style="cyan", width=30)
        table.add_column("Severity", style="yellow", width=10)
        table.add_column("Resource Types", style="green", width=20)
        table.add_column("Controls", style="magenta", width=15)

        for check in sorted(checks_list, key=lambda c: c.id):
            sev_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}
            sev_display = f"[{sev_color[check.severity]}]{check.severity}[/{sev_color[check.severity]}]"
            resources = ", ".join(check.resource_types[:2])
            if len(check.resource_types) > 2:
                resources += f" +{len(check.resource_types) - 2}"
            controls_str = ", ".join(check.frameworks.get("soc2", []))

            table.add_row(check.id, sev_display, resources, controls_str)

        console.print(table)
    else:
        console.print(f"[yellow]Framework '{framework_id}' not found or not yet implemented.[/yellow]")


# =============================================================================
# Remediate Commands
# =============================================================================


@cli.group()
@click.pass_context
def remediate(ctx: click.Context) -> None:
    """Automated remediation for compliance issues."""
    pass


@remediate.command("plan")
@click.option("--scan-file", "-s", type=click.Path(exists=True), required=True, help="JSON file from previous scan")
@click.option("--framework", "-f", type=click.Choice(["soc2"]), default="soc2", help="Framework")
@click.option("--output", "-o", type=click.Path(), help="Output file for remediation plan")
@click.pass_context
def remediate_plan(
    ctx: click.Context,
    scan_file: str,
    framework: str,
    output: str | None,
) -> None:
    """Create a remediation plan from scan results."""
    import json as json_module
    from attestful.remediation import (
        RemediationPlan,
        RiskLevel,
        get_remediation_action,
    )

    console.print(f"[bold blue]Creating Remediation Plan[/bold blue]")
    console.print()

    # Load scan results
    console.print(f"Loading scan results from {scan_file}...")
    try:
        scan_data = json_module.loads(Path(scan_file).read_text())
        failed_results = [r for r in scan_data.get("results", []) if not r.get("passed")]
        console.print(f"  Found {len(failed_results)} failed checks")
    except Exception as e:
        console.print(f"[red]Failed to load scan file: {e}[/red]")
        return

    if not failed_results:
        console.print("[green]No failed checks to remediate![/green]")
        return

    # Create remediation plan
    plan = RemediationPlan()
    no_remediation = []

    for result in failed_results:
        action = get_remediation_action(
            check_id=result["check_id"],
            resource_id=result["resource_id"],
            resource_data={"type": result["resource_type"]},
            dry_run=True,  # Plan is always dry-run
        )
        if action:
            plan.add_action(action)
        else:
            no_remediation.append(result)

    # Show plan summary
    summary = plan.get_summary()
    console.print()
    console.print("[bold]Remediation Plan Summary:[/bold]")
    console.print(f"  Total Actions: {summary['total_actions']}")
    console.print(f"  [green]Low Risk:[/green] {summary['by_risk_level']['low']}")
    console.print(f"  [yellow]Medium Risk:[/yellow] {summary['by_risk_level']['medium']}")
    console.print(f"  [red]High Risk:[/red] {summary['by_risk_level']['high']}")
    console.print(f"  [red bold]Critical Risk:[/red bold] {summary['by_risk_level']['critical']}")

    if no_remediation:
        console.print()
        console.print(f"[dim]No automated remediation available for {len(no_remediation)} checks[/dim]")

    # Show actions by risk level
    console.print()
    console.print("[bold]Planned Actions:[/bold]")

    for risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
        actions = plan.get_actions_by_risk(risk_level)
        if actions:
            color = {"low": "green", "medium": "yellow", "high": "red", "critical": "red bold"}[risk_level.value]
            console.print(f"\n  [{color}]{risk_level.value.upper()} RISK ({len(actions)} actions)[/{color}]")
            for action in actions[:5]:
                console.print(f"    - {action.get_description()}")
            if len(actions) > 5:
                console.print(f"    ... and {len(actions) - 5} more")

    # Save plan if output specified
    if output:
        plan_data = {
            "created_at": plan.created_at.isoformat(),
            "source_scan": scan_file,
            "summary": summary,
            "actions": [
                {
                    "action_id": a.action_id,
                    "check_id": a.check_id,
                    "resource_id": a.resource_id,
                    "resource_type": a.resource_type,
                    "risk_level": a.get_risk_level().value,
                    "description": a.get_description(),
                }
                for a in plan.actions
            ],
            "no_remediation_available": [
                {
                    "check_id": r["check_id"],
                    "resource_id": r["resource_id"],
                    "resource_type": r["resource_type"],
                }
                for r in no_remediation
            ],
        }
        Path(output).write_text(json_module.dumps(plan_data, indent=2))
        console.print()
        console.print(f"[dim]Plan saved to {output}[/dim]")

    console.print()
    console.print("[bold]Next Steps:[/bold]")
    console.print("  1. Review the plan above")
    console.print("  2. Run dry-run: [cyan]attestful remediate run --scan-file <file> --dry-run[/cyan]")
    console.print("  3. Execute: [cyan]attestful remediate run --scan-file <file> --auto-approve[/cyan]")


@remediate.command("run")
@click.option("--scan-file", "-s", type=click.Path(exists=True), required=True, help="JSON file from previous scan")
@click.option("--dry-run", is_flag=True, help="Simulate remediation without making changes")
@click.option("--auto-approve", is_flag=True, help="Skip approval prompts")
@click.option("--max-risk", type=click.Choice(["low", "medium", "high", "critical"]), default="medium", help="Maximum risk level to auto-approve")
@click.option("--skip-high-risk", is_flag=True, default=True, help="Skip high and critical risk actions")
@click.option("--output", "-o", type=click.Path(), help="Output file for remediation results")
@click.option("--region", "-r", default="us-east-1", help="AWS region")
@click.pass_context
def remediate_run(
    ctx: click.Context,
    scan_file: str,
    dry_run: bool,
    auto_approve: bool,
    max_risk: str,
    skip_high_risk: bool,
    output: str | None,
    region: str,
) -> None:
    """Execute remediation for failed compliance checks."""
    import asyncio
    import json as json_module
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from attestful.remediation import (
        RemediationEngine,
        RemediationPlan,
        RemediationStatus,
        RiskLevel,
        get_remediation_action,
    )

    console.print(f"[bold blue]{'[DRY RUN] ' if dry_run else ''}Executing Remediation[/bold blue]")
    console.print(f"  Max Risk Level: {max_risk}")
    console.print(f"  Skip High Risk: {skip_high_risk}")
    console.print(f"  Auto Approve: {auto_approve}")
    console.print()

    # Load scan results
    console.print(f"Loading scan results from {scan_file}...")
    try:
        scan_data = json_module.loads(Path(scan_file).read_text())
        failed_results = [r for r in scan_data.get("results", []) if not r.get("passed")]
        console.print(f"  Found {len(failed_results)} failed checks")
    except Exception as e:
        console.print(f"[red]Failed to load scan file: {e}[/red]")
        return

    if not failed_results:
        console.print("[green]No failed checks to remediate![/green]")
        return

    # Create remediation plan
    plan = RemediationPlan()

    for result in failed_results:
        action = get_remediation_action(
            check_id=result["check_id"],
            resource_id=result["resource_id"],
            resource_data={"type": result["resource_type"], "name": result["resource_id"]},
            region=region,
            dry_run=dry_run,
        )
        if action:
            plan.add_action(action)

    if not plan.actions:
        console.print("[yellow]No automated remediation available for any failed checks.[/yellow]")
        return

    summary = plan.get_summary()
    console.print()
    console.print("[bold]Remediation Plan:[/bold]")
    console.print(f"  Total Actions: {summary['total_actions']}")
    console.print()

    # Confirm if not auto-approve and not dry-run
    if not dry_run and not auto_approve:
        if not click.confirm("Proceed with remediation?", default=False):
            console.print("[yellow]Remediation cancelled.[/yellow]")
            return

    # Create remediation engine
    risk_map = {
        "low": RiskLevel.LOW,
        "medium": RiskLevel.MEDIUM,
        "high": RiskLevel.HIGH,
        "critical": RiskLevel.CRITICAL,
    }

    # Approval callback for interactive mode
    def approval_callback(action):
        if dry_run:
            return True
        risk = action.get_risk_level()
        risk_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "red bold"}
        console.print()
        console.print(f"[{risk_color[risk.value]}]Risk: {risk.value.upper()}[/{risk_color[risk.value]}]")
        console.print(f"Action: {action.get_description()}")
        console.print(f"Resource: {action.resource_id}")
        return click.confirm("Approve this remediation?", default=risk == RiskLevel.LOW)

    engine = RemediationEngine(
        max_concurrent=3,
        require_approval=not auto_approve and not dry_run,
        approval_callback=approval_callback if not auto_approve else None,
        max_risk_level=risk_map[max_risk],
    )

    # Execute plan
    async def run_remediation():
        return await engine.execute_plan(
            plan,
            auto_approve=auto_approve or dry_run,
            skip_high_risk=skip_high_risk,
        )

    console.print()
    console.print("[bold]Executing Remediation...[/bold]")

    try:
        results = asyncio.run(run_remediation())
    except Exception as e:
        console.print(f"[red]Remediation failed: {e}[/red]")
        return

    # Show results
    success_count = sum(1 for r in results if r.status == RemediationStatus.SUCCESS)
    failed_count = sum(1 for r in results if r.status == RemediationStatus.FAILED)
    skipped_count = sum(1 for r in results if r.status == RemediationStatus.SKIPPED)
    rolled_back_count = sum(1 for r in results if r.status == RemediationStatus.ROLLED_BACK)

    console.print()
    console.print("[bold]Remediation Results:[/bold]")
    console.print(f"  [green]Success:[/green] {success_count}")
    console.print(f"  [red]Failed:[/red] {failed_count}")
    console.print(f"  [yellow]Skipped:[/yellow] {skipped_count}")
    console.print(f"  [cyan]Rolled Back:[/cyan] {rolled_back_count}")

    # Show details for failed/rolled back
    failed_results_list = [r for r in results if r.status in [RemediationStatus.FAILED, RemediationStatus.ROLLED_BACK]]
    if failed_results_list:
        console.print()
        console.print("[bold red]Failed/Rolled Back Actions:[/bold red]")
        for r in failed_results_list:
            console.print(f"  - {r.check_id} ({r.resource_id})")
            console.print(f"    Status: {r.status.value}")
            console.print(f"    Message: {r.message}")
            if r.error:
                console.print(f"    Error: {r.error}")

    # Show changes made
    changes_made = [r for r in results if r.changes_made]
    if changes_made:
        console.print()
        console.print("[bold]Changes Made:[/bold]")
        for r in changes_made:
            for change in r.changes_made:
                prefix = "[DRY RUN] " if r.dry_run else ""
                console.print(f"  - {prefix}{change}")

    # Save results if output specified
    if output:
        results_data = {
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "source_scan": scan_file,
            "dry_run": dry_run,
            "summary": {
                "total": len(results),
                "success": success_count,
                "failed": failed_count,
                "skipped": skipped_count,
                "rolled_back": rolled_back_count,
            },
            "results": [r.to_dict() for r in results],
        }
        Path(output).write_text(json_module.dumps(results_data, indent=2))
        console.print()
        console.print(f"[dim]Results saved to {output}[/dim]")


@remediate.command("list")
@click.pass_context
def remediate_list(ctx: click.Context) -> None:
    """List available remediation actions."""
    from attestful.remediation import REMEDIATION_REGISTRY, RiskLevel
    from attestful.remediation.aws import (
        EnableS3BucketVersioningAction,
        EnableS3BucketEncryptionAction,
        BlockS3PublicAccessAction,
        UpdateIAMPasswordPolicyAction,
        EnableCloudTrailLogValidationAction,
        RemoveOpenSSHAccessAction,
        EnableKMSKeyRotationAction,
    )

    # Create a dummy instance to get metadata
    action_info = {
        "EnableS3BucketVersioningAction": ("S3", "Enable versioning on S3 bucket", RiskLevel.LOW),
        "EnableS3BucketEncryptionAction": ("S3", "Enable default encryption on S3 bucket", RiskLevel.LOW),
        "BlockS3PublicAccessAction": ("S3", "Block public access on S3 bucket", RiskLevel.MEDIUM),
        "UpdateIAMPasswordPolicyAction": ("IAM", "Update IAM password policy", RiskLevel.MEDIUM),
        "EnableCloudTrailLogValidationAction": ("CloudTrail", "Enable log file validation", RiskLevel.LOW),
        "RemoveOpenSSHAccessAction": ("EC2", "Remove unrestricted SSH access", RiskLevel.HIGH),
        "EnableKMSKeyRotationAction": ("KMS", "Enable automatic key rotation", RiskLevel.LOW),
    }

    table = Table(title="Available Remediation Actions")
    table.add_column("Service", style="cyan", width=12)
    table.add_column("Action", style="white", width=40)
    table.add_column("Risk Level", style="yellow", width=12)
    table.add_column("Check IDs", style="green", width=30)

    # Group by action class
    action_check_map: dict[type, list[str]] = {}
    for check_id, action_class in REMEDIATION_REGISTRY.items():
        if action_class not in action_check_map:
            action_check_map[action_class] = []
        action_check_map[action_class].append(check_id)

    for action_class, check_ids in action_check_map.items():
        class_name = action_class.__name__
        if class_name in action_info:
            service, description, risk = action_info[class_name]
            risk_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "red bold"}
            risk_display = f"[{risk_color[risk.value]}]{risk.value.upper()}[/{risk_color[risk.value]}]"

            checks_str = check_ids[0]
            if len(check_ids) > 1:
                checks_str += f" (+{len(check_ids) - 1} more)"

            table.add_row(service, description, risk_display, checks_str)

    console.print(table)
    console.print()
    console.print("[dim]Risk Levels:[/dim]")
    console.print("  [green]LOW[/green]: Safe, easily reversible changes")
    console.print("  [yellow]MEDIUM[/yellow]: May affect functionality, reversible")
    console.print("  [red]HIGH[/red]: Significant impact, may affect availability")
    console.print("  [red bold]CRITICAL[/red bold]: High risk, manual review recommended")


# =============================================================================
# Configure Commands
# =============================================================================


@cli.group()
@click.pass_context
def configure(ctx: click.Context) -> None:
    """Configure Attestful settings and credentials."""
    pass


@configure.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing configuration")
@click.pass_context
def configure_init(ctx: click.Context, force: bool) -> None:
    """Initialize Attestful configuration."""
    from attestful.config import get_settings
    from attestful.storage.database import init_database

    console.print("[bold blue]Initializing Attestful[/bold blue]")

    settings = get_settings()

    # Create directories
    console.print("  Creating directories...", end=" ")
    try:
        settings.ensure_directories()
        console.print("[green]Done[/green]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        return

    # Initialize database
    console.print("  Creating database...", end=" ")
    try:
        init_database()
        console.print("[green]Done[/green]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        return

    console.print()
    console.print("[green]Attestful initialized successfully![/green]")
    console.print(f"  Data directory: [cyan]{settings.data_dir}[/cyan]")
    console.print()
    console.print("Next steps:")
    console.print("  1. Configure credentials: [cyan]attestful configure credentials --platform aws[/cyan]")
    console.print("  2. Run a scan: [cyan]attestful scan aws[/cyan]")
    console.print("  3. View results: [cyan]attestful scan list[/cyan]")


@configure.command("credentials")
@click.option("--platform", "-p", required=True, help="Platform to configure")
@click.option("--name", "-n", default="default", help="Credential name/alias")
@click.option("--test", is_flag=True, help="Test credentials after saving")
@click.option("--delete", "delete_cred", is_flag=True, help="Delete credential")
@click.pass_context
def configure_credentials(
    ctx: click.Context,
    platform: str,
    name: str,
    test: bool,
    delete_cred: bool,
) -> None:
    """Configure platform credentials."""
    from attestful.config import CredentialStore, get_credential_store

    store = get_credential_store()

    if delete_cred:
        if store.delete(platform, name):
            console.print(f"[green]Deleted credential: {platform}/{name}[/green]")
        else:
            console.print(f"[yellow]Credential not found: {platform}/{name}[/yellow]")
        return

    console.print(f"[bold blue]Configure {platform} Credentials[/bold blue]")
    console.print(f"  Name: {name}")
    console.print()

    # Get required fields for platform
    schema = CredentialStore.PLATFORM_SCHEMAS.get(platform, set())
    if not schema:
        console.print(f"[yellow]Unknown platform: {platform}[/yellow]")
        console.print("Supported platforms:")
        for p in sorted(CredentialStore.PLATFORM_SCHEMAS.keys()):
            console.print(f"  - {p}")
        return

    # Prompt for each required field
    data: dict[str, str] = {}
    for field in sorted(schema):
        is_secret = any(s in field.lower() for s in ["secret", "password", "token", "key"])
        value = click.prompt(
            f"  {field}",
            hide_input=is_secret,
            default="",
            show_default=False,
        )
        if value:
            data[field] = value

    if not data:
        console.print("[yellow]No credentials provided. Cancelled.[/yellow]")
        return

    try:
        store.set(platform, name, data, validate=True)
        console.print()
        console.print(f"[green]Credentials saved: {platform}/{name}[/green]")

        if test:
            console.print()
            console.print("Testing credentials...", end=" ")
            success, message = store.test_credential(platform, name)
            if success:
                console.print(f"[green]{message}[/green]")
            else:
                console.print(f"[red]{message}[/red]")

    except Exception as e:
        console.print(f"[red]Failed to save credentials: {e}[/red]")


@configure.command("show")
@click.option("--secrets", is_flag=True, help="Show secret values (use with caution)")
@click.pass_context
def configure_show(ctx: click.Context, secrets: bool) -> None:
    """Show current configuration."""
    from attestful.config import get_settings, get_credential_store

    settings = get_settings()
    store = get_credential_store()

    # Settings table
    table = Table(title="Current Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    config_items = [
        ("Data Directory", str(settings.data_dir)),
        ("Evidence Directory", str(settings.effective_evidence_dir)),
        ("Database URL", settings.database_url if secrets else "***"),
        ("Log Level", settings.log_level),
        ("Environment", settings.app_env),
        ("Debug Mode", str(settings.debug)),
        ("Collector Timeout", f"{settings.collector_timeout}s"),
        ("Collector Retries", str(settings.collector_retry_attempts)),
    ]

    for setting, value in config_items:
        table.add_row(setting, value)

    console.print(table)
    console.print()

    # Credentials table
    all_creds = store.list_all()
    if all_creds:
        cred_table = Table(title="Configured Credentials")
        cred_table.add_column("Platform", style="cyan")
        cred_table.add_column("Name", style="green")
        cred_table.add_column("Fields", style="white")

        for platform, names in all_creds.items():
            for name in names:
                cred = store.get(platform, name)
                if cred:
                    fields = ", ".join(sorted(cred.data.keys()))
                    cred_table.add_row(platform, name, fields)

        console.print(cred_table)
    else:
        console.print("[dim]No credentials configured.[/dim]")
        console.print("Run 'attestful configure credentials --platform <platform>' to add credentials.")


@configure.command("platforms")
@click.pass_context
def configure_platforms(ctx: click.Context) -> None:
    """List supported platforms for credential configuration."""
    from attestful.config import CredentialStore

    table = Table(title="Supported Platforms")
    table.add_column("Platform", style="cyan")
    table.add_column("Required Fields", style="white")

    for platform in sorted(CredentialStore.PLATFORM_SCHEMAS.keys()):
        fields = CredentialStore.PLATFORM_SCHEMAS[platform]
        table.add_row(platform, ", ".join(sorted(fields)))

    console.print(table)


@configure.command("rotate-key")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def configure_rotate_key(ctx: click.Context, yes: bool) -> None:
    """Rotate the credential encryption key."""
    from attestful.config import get_credential_store

    if not yes:
        click.confirm(
            "This will re-encrypt all credentials with a new key. Continue?",
            abort=True,
        )

    store = get_credential_store()
    store.rotate_key()
    console.print("[green]Encryption key rotated successfully.[/green]")


# =============================================================================
# Entry Point
# =============================================================================


def main() -> None:
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unhandled error")
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
