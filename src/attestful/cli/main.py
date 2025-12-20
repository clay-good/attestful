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
    type=click.Choice(["soc2", "cis", "nist-800-53", "iso-27001", "hitrust", "all"]),
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

        attestful scan soc2 --provider azure

        attestful scan soc2 --provider aws --severity high

        attestful scan soc2 --provider aws --control CC6.1 --control CC7.2

        attestful scan soc2 --provider aws -o results.json --generate-oscal
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.cloud import AWSCollector, AWSCollectorConfig, AzureCollector, AzureCollectorConfig
    from attestful.frameworks import create_soc2_evaluator, get_soc2_framework, SOC2_CONTROLS

    console.print(f"[bold blue]Attestful SOC 2 Type II Compliance Scan[/bold blue]")
    console.print(f"  Provider: {provider}")
    console.print(f"  Regions: {', '.join(region) if region else 'all'}")
    console.print(f"  Min Severity: {severity}")
    if control:
        console.print(f"  Controls: {', '.join(control)}")
    console.print()

    # Create provider-specific collector
    collector = None
    if provider == "aws":
        config = AWSCollectorConfig(
            profile=profile,
            regions=list(region) if region else [],
        )
        collector = AWSCollector(config=config)
    elif provider == "azure":
        try:
            azure_config = AzureCollectorConfig(
                tenant_id=os.environ.get("AZURE_TENANT_ID"),
                client_id=os.environ.get("AZURE_CLIENT_ID"),
                client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
            )
            collector = AzureCollector(config=azure_config)
        except Exception as e:
            console.print(f"[red]Failed to initialize Azure collector: {e}[/red]")
            console.print("Install Azure SDK: pip install azure-identity azure-mgmt-resource azure-mgmt-compute azure-mgmt-network azure-mgmt-storage")
            return
    elif provider == "gcp":
        console.print(f"[yellow]Provider 'gcp' not yet implemented. Using AWS.[/yellow]")
        config = AWSCollectorConfig(
            profile=profile,
            regions=list(region) if region else [],
        )
        collector = AWSCollector(config=config)
        provider = "aws"
    elif provider == "all":
        console.print(f"[yellow]Multi-provider scan not yet implemented. Using AWS.[/yellow]")
        config = AWSCollectorConfig(
            profile=profile,
            regions=list(region) if region else [],
        )
        collector = AWSCollector(config=config)
        provider = "aws"
    else:
        console.print(f"[red]Unknown provider: {provider}[/red]")
        return

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Validating {provider.upper()} credentials...", total=None)
        if not collector.validate_credentials():
            console.print(f"[red]Failed to validate {provider.upper()} credentials.[/red]")
            if provider == "aws":
                console.print("Run 'attestful configure credentials --platform aws' to set up credentials.")
            elif provider == "azure":
                console.print("Options for authentication:")
                console.print("  1. Run 'az login' to use Azure CLI credentials")
                console.print("  2. Set environment variables: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect resources
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Collecting {provider.upper()} resources...", total=None)
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

    # Create SOC 2 evaluator with provider-specific checks
    evaluator = create_soc2_evaluator(provider=provider)

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


@scan.command("azure")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["soc2", "cis", "nist-800-53", "iso-27001", "hitrust", "all"]),
    default="all",
    help="Compliance framework to check against",
)
@click.option(
    "--subscription",
    "-s",
    multiple=True,
    help="Azure subscription IDs to scan (can be specified multiple times)",
)
@click.option(
    "--resource-group",
    "-g",
    multiple=True,
    help="Resource groups to scan (can be specified multiple times)",
)
@click.option(
    "--tenant-id",
    help="Azure tenant ID (or use AZURE_TENANT_ID env var)",
)
@click.option(
    "--client-id",
    help="Azure client/app ID (or use AZURE_CLIENT_ID env var)",
)
@click.option(
    "--client-secret",
    help="Azure client secret (or use AZURE_CLIENT_SECRET env var)",
)
@click.option(
    "--use-managed-identity",
    is_flag=True,
    help="Use Azure Managed Identity for authentication",
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
def scan_azure(
    ctx: click.Context,
    framework: str,
    subscription: tuple[str, ...],
    resource_group: tuple[str, ...],
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    use_managed_identity: bool,
    severity: str,
    output: str | None,
) -> None:
    """Scan Azure infrastructure for compliance issues.

    Scans Azure cloud resources for security and compliance issues.
    Supports SOC 2, CIS Benchmarks, and NIST 800-53 frameworks.

    Authentication can be provided via:
    - Service principal (--tenant-id, --client-id, --client-secret)
    - Managed identity (--use-managed-identity)
    - Azure CLI credentials (az login)
    - Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)

    Examples:

        attestful scan azure

        attestful scan azure --subscription sub-123 --framework soc2

        attestful scan azure --use-managed-identity --severity high

        attestful scan azure -o results.json
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.cloud import AzureCollector, AzureCollectorConfig
    from attestful.core import create_default_evaluator

    console.print(f"[bold blue]Attestful Azure Scan[/bold blue]")
    console.print(f"  Framework: {framework}")
    console.print(f"  Subscriptions: {', '.join(subscription) if subscription else 'all accessible'}")
    if resource_group:
        console.print(f"  Resource Groups: {', '.join(resource_group)}")
    console.print(f"  Min Severity: {severity}")
    console.print()

    # Build config from options and environment
    config = AzureCollectorConfig(
        tenant_id=tenant_id or os.environ.get("AZURE_TENANT_ID"),
        client_id=client_id or os.environ.get("AZURE_CLIENT_ID"),
        client_secret=client_secret or os.environ.get("AZURE_CLIENT_SECRET"),
        subscription_ids=list(subscription) if subscription else [],
        resource_groups=list(resource_group) if resource_group else [],
        use_managed_identity=use_managed_identity,
    )

    try:
        collector = AzureCollector(config=config)
    except Exception as e:
        console.print(f"[red]Failed to initialize Azure collector: {e}[/red]")
        return

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Azure credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate Azure credentials.[/red]")
            console.print("Options for authentication:")
            console.print("  1. Run 'az login' to use Azure CLI credentials")
            console.print("  2. Set environment variables: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET")
            console.print("  3. Use --tenant-id, --client-id, --client-secret options")
            console.print("  4. Use --use-managed-identity when running in Azure")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect resources
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Azure resources...", total=None)
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
            "scan_type": "azure",
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


@scan.command("gcp")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["soc2", "cis", "nist-800-53", "iso-27001", "hitrust", "all"]),
    default="all",
    help="Compliance framework to check against",
)
@click.option(
    "--project",
    "-p",
    multiple=True,
    help="GCP project IDs to scan (can be specified multiple times)",
)
@click.option(
    "--zone",
    "-z",
    multiple=True,
    help="Zones to scan (can be specified multiple times)",
)
@click.option(
    "--region",
    "-r",
    multiple=True,
    help="Regions to scan (can be specified multiple times)",
)
@click.option(
    "--credentials-file",
    type=click.Path(exists=True),
    help="Path to GCP service account JSON key file (or use GOOGLE_APPLICATION_CREDENTIALS env var)",
)
@click.option(
    "--use-default-credentials",
    is_flag=True,
    default=True,
    help="Use Application Default Credentials (default: True)",
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
def scan_gcp(
    ctx: click.Context,
    framework: str,
    project: tuple[str, ...],
    zone: tuple[str, ...],
    region: tuple[str, ...],
    credentials_file: str | None,
    use_default_credentials: bool,
    severity: str,
    output: str | None,
) -> None:
    """Scan GCP infrastructure for compliance issues.

    Scans Google Cloud Platform resources for security and compliance issues.
    Supports SOC 2, CIS Benchmarks, and NIST 800-53 frameworks.

    Authentication can be provided via:
    - Service account key file (--credentials-file)
    - Application Default Credentials (gcloud auth application-default login)
    - Environment variable (GOOGLE_APPLICATION_CREDENTIALS)
    - Workload Identity when running on GCP

    Examples:

        attestful scan gcp

        attestful scan gcp --project my-project --framework soc2

        attestful scan gcp --credentials-file /path/to/key.json

        attestful scan gcp -p project1 -p project2 --severity high

        attestful scan gcp -o results.json
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.cloud import GCPCollector, GCPCollectorConfig
    from attestful.core import create_default_evaluator

    console.print(f"[bold blue]Attestful GCP Scan[/bold blue]")
    console.print(f"  Framework: {framework}")
    console.print(f"  Projects: {', '.join(project) if project else 'all accessible'}")
    if zone:
        console.print(f"  Zones: {', '.join(zone)}")
    if region:
        console.print(f"  Regions: {', '.join(region)}")
    console.print(f"  Min Severity: {severity}")
    console.print()

    # Determine credentials file
    creds_file = credentials_file or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")

    # Build config from options
    config = GCPCollectorConfig(
        project_ids=list(project) if project else [],
        zones=list(zone) if zone else [],
        regions=list(region) if region else [],
        credentials_file=creds_file,
        use_default_credentials=use_default_credentials and not creds_file,
    )

    try:
        collector = GCPCollector(config=config)
    except Exception as e:
        console.print(f"[red]Failed to initialize GCP collector: {e}[/red]")
        return

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating GCP credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate GCP credentials.[/red]")
            console.print("Options for authentication:")
            console.print("  1. Run 'gcloud auth application-default login'")
            console.print("  2. Set GOOGLE_APPLICATION_CREDENTIALS environment variable")
            console.print("  3. Use --credentials-file /path/to/service-account-key.json")
            console.print("  4. Use Workload Identity when running on GCP")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect resources
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting GCP resources...", total=None)
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
            "scan_type": "gcp",
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


@scan.command("kubernetes")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["soc2", "cis", "nist-800-53", "iso-27001", "hitrust", "all"]),
    default="all",
    help="Compliance framework to check against",
)
@click.option(
    "--namespace",
    "-n",
    multiple=True,
    help="Kubernetes namespaces to scan (can be specified multiple times)",
)
@click.option(
    "--exclude-namespace",
    multiple=True,
    default=["kube-system", "kube-public", "kube-node-lease"],
    help="Namespaces to exclude from scanning",
)
@click.option(
    "--kubeconfig",
    type=click.Path(exists=True),
    help="Path to kubeconfig file (or use KUBECONFIG env var)",
)
@click.option(
    "--context",
    help="Kubernetes context to use",
)
@click.option(
    "--in-cluster",
    is_flag=True,
    help="Use in-cluster config (when running inside Kubernetes)",
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
def scan_kubernetes(
    ctx: click.Context,
    framework: str,
    namespace: tuple[str, ...],
    exclude_namespace: tuple[str, ...],
    kubeconfig: str | None,
    context: str | None,
    in_cluster: bool,
    severity: str,
    output: str | None,
) -> None:
    """Scan Kubernetes clusters for compliance issues.

    Scans Kubernetes resources for security and compliance issues.
    Supports SOC 2, CIS Kubernetes Benchmark, and NIST 800-53 frameworks.

    Authentication can be provided via:
    - Kubeconfig file (--kubeconfig or KUBECONFIG env var)
    - Specific context (--context)
    - In-cluster config when running inside Kubernetes (--in-cluster)

    Examples:

        attestful scan kubernetes

        attestful scan kubernetes --namespace production --framework soc2

        attestful scan kubernetes --kubeconfig ~/.kube/config --context my-cluster

        attestful scan kubernetes --in-cluster

        attestful scan kubernetes -n production -n staging --severity high

        attestful scan kubernetes -o results.json
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.containers import KubernetesCollector, KubernetesCollectorConfig
    from attestful.core import create_default_evaluator

    console.print(f"[bold blue]Attestful Kubernetes Scan[/bold blue]")
    console.print(f"  Framework: {framework}")
    console.print(f"  Namespaces: {', '.join(namespace) if namespace else 'all (excluding system)'}")
    if exclude_namespace:
        console.print(f"  Excluded: {', '.join(exclude_namespace)}")
    console.print(f"  Min Severity: {severity}")
    console.print()

    # Determine kubeconfig
    kube_config = kubeconfig or os.environ.get("KUBECONFIG")

    # Build config from options
    config = KubernetesCollectorConfig(
        kubeconfig_path=kube_config,
        context=context,
        in_cluster=in_cluster,
        namespaces=list(namespace) if namespace else [],
        exclude_namespaces=list(exclude_namespace) if exclude_namespace else [],
    )

    try:
        collector = KubernetesCollector(config=config)
    except Exception as e:
        console.print(f"[red]Failed to initialize Kubernetes collector: {e}[/red]")
        console.print()
        console.print("Make sure you have:")
        console.print("  1. kubectl configured and working")
        console.print("  2. The 'kubernetes' Python package installed: pip install kubernetes")
        return

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Connecting to Kubernetes cluster...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to connect to Kubernetes cluster.[/red]")
                console.print("Options for authentication:")
                console.print("  1. Configure kubectl: kubectl config use-context <context>")
                console.print("  2. Set KUBECONFIG environment variable")
                console.print("  3. Use --kubeconfig /path/to/kubeconfig")
                console.print("  4. Use --in-cluster when running inside Kubernetes")
                return
            progress.update(task, description="[green]Connected to cluster[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect resources
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Kubernetes resources...", total=None)
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
            "scan_type": "kubernetes",
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


@collect.command("kubernetes")
@click.option(
    "--namespace",
    "-n",
    multiple=True,
    help="Kubernetes namespaces to collect from (can be specified multiple times)",
)
@click.option(
    "--exclude-namespace",
    multiple=True,
    default=["kube-system", "kube-public", "kube-node-lease"],
    help="Namespaces to exclude from collection",
)
@click.option(
    "--kubeconfig",
    type=click.Path(exists=True),
    help="Path to kubeconfig file (or use KUBECONFIG env var)",
)
@click.option(
    "--context",
    help="Kubernetes context to use",
)
@click.option(
    "--in-cluster",
    is_flag=True,
    help="Use in-cluster config (when running inside Kubernetes)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    help="Evidence types to collect (cluster_info, rbac_config, network_policies, pod_security, secrets_inventory, resource_quotas, limit_ranges, admission_controllers)",
)
@click.option("--output", "-o", type=click.Path(), help="Output directory for evidence")
@click.pass_context
def collect_kubernetes(
    ctx: click.Context,
    namespace: tuple[str, ...],
    exclude_namespace: tuple[str, ...],
    kubeconfig: str | None,
    context: str | None,
    in_cluster: bool,
    types: tuple[str, ...],
    output: str | None,
) -> None:
    """Collect evidence from Kubernetes clusters.

    Collects compliance and audit evidence from Kubernetes clusters including
    RBAC configurations, network policies, pod security settings, and more.

    Authentication can be provided via:
    - Kubeconfig file (--kubeconfig or KUBECONFIG env var)
    - Specific context (--context)
    - In-cluster config when running inside Kubernetes (--in-cluster)

    Examples:

        attestful collect kubernetes

        attestful collect kubernetes --namespace production

        attestful collect kubernetes --kubeconfig ~/.kube/config --context my-cluster

        attestful collect kubernetes --in-cluster

        attestful collect kubernetes -t rbac_config -t network_policies

        attestful collect kubernetes -o ./evidence
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.containers import KubernetesCollector, KubernetesCollectorConfig
    from attestful.config import get_settings
    from attestful.storage import EvidenceStore

    console.print("[bold blue]Collecting Kubernetes Evidence[/bold blue]")
    console.print(f"  Namespaces: {', '.join(namespace) if namespace else 'all (excluding system)'}")
    if exclude_namespace:
        console.print(f"  Excluded: {', '.join(exclude_namespace)}")
    if types:
        console.print(f"  Evidence types: {', '.join(types)}")
    console.print()

    # Determine kubeconfig
    kube_config = kubeconfig or os.environ.get("KUBECONFIG")

    # Build config from options
    config = KubernetesCollectorConfig(
        kubeconfig_path=kube_config,
        context=context,
        in_cluster=in_cluster,
        namespaces=list(namespace) if namespace else [],
        exclude_namespaces=list(exclude_namespace) if exclude_namespace else [],
    )

    try:
        collector = KubernetesCollector(config=config)
    except Exception as e:
        console.print(f"[red]Failed to initialize Kubernetes collector: {e}[/red]")
        console.print()
        console.print("Make sure you have:")
        console.print("  1. kubectl configured and working")
        console.print("  2. The 'kubernetes' Python package installed: pip install kubernetes")
        return

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Connecting to Kubernetes cluster...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to connect to Kubernetes cluster.[/red]")
                console.print("Options for authentication:")
                console.print("  1. Configure kubectl: kubectl config use-context <context>")
                console.print("  2. Set KUBECONFIG environment variable")
                console.print("  3. Use --kubeconfig /path/to/kubeconfig")
                console.print("  4. Use --in-cluster when running inside Kubernetes")
                return
            progress.update(task, description="[green]Connected to cluster[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Kubernetes evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
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


@collect.command("datadog")
@click.option(
    "--types",
    "-t",
    multiple=True,
    help="Evidence types to collect (monitors, dashboards, users, api_keys, audit_logs, security_rules, slos, synthetics)",
)
@click.option("--output", "-o", type=click.Path(), help="Output directory for evidence")
@click.option("--days", default=30, help="Number of days of history to collect for audit logs")
@click.option(
    "--site",
    default="datadoghq.com",
    help="Datadog site (datadoghq.com, datadoghq.eu, us3.datadoghq.com, etc.)",
)
@click.pass_context
def collect_datadog(
    ctx: click.Context,
    types: tuple[str, ...],
    output: str | None,
    days: int,
    site: str,
) -> None:
    """Collect evidence from Datadog.

    Collects monitoring and observability evidence from Datadog including
    monitors, dashboards, users, API keys, audit logs, security rules,
    SLOs, and synthetic tests.

    Authentication requires both API key and Application key, which can be
    configured via 'attestful configure credentials --platform datadog' or
    set via environment variables DD_API_KEY and DD_APP_KEY.

    Examples:

        attestful collect datadog

        attestful collect datadog -t monitors -t audit_logs

        attestful collect datadog --site datadoghq.eu

        attestful collect datadog --days 90 -o ./evidence
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.platforms import DatadogCollector, DatadogCollectorConfig
    from attestful.config import get_credential_store, get_settings
    from attestful.storage import EvidenceStore

    console.print("[bold blue]Collecting Datadog Evidence[/bold blue]")
    console.print(f"  Site: {site}")
    if types:
        console.print(f"  Evidence types: {', '.join(types)}")
    console.print(f"  History: {days} days")
    console.print()

    # Get credentials from store or environment
    store = get_credential_store()
    cred = store.get_default("datadog")

    api_key = ""
    app_key = ""

    if cred:
        api_key = cred.data.get("api_key", "")
        app_key = cred.data.get("app_key", "")
    else:
        # Fall back to environment variables
        api_key = os.environ.get("DD_API_KEY", "")
        app_key = os.environ.get("DD_APP_KEY", "")

    if not api_key or not app_key:
        console.print("[red]No Datadog credentials configured.[/red]")
        console.print("Run 'attestful configure credentials --platform datadog' to set up credentials,")
        console.print("or set DD_API_KEY and DD_APP_KEY environment variables.")
        return

    # Create collector
    config = DatadogCollectorConfig(
        api_key=api_key,
        app_key=app_key,
        site=site,
        days_of_history=days,
    )
    collector = DatadogCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Datadog credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate Datadog credentials.[/red]")
            console.print("Please verify your API key and Application key.")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Datadog evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
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


@collect.command("gitlab")
@click.option("--group", "-g", help="GitLab group ID or path")
@click.option(
    "--types",
    "-t",
    multiple=True,
    help="Evidence types to collect (projects, protected_branches, merge_requests, pipelines, members, vulnerabilities, audit_events, deploy_keys)",
)
@click.option("--output", "-o", type=click.Path(), help="Output directory for evidence")
@click.option("--days", default=90, help="Number of days of history to collect")
@click.option(
    "--url",
    default="https://gitlab.com",
    help="GitLab instance URL (for self-hosted)",
)
@click.option("--include-subgroups/--no-subgroups", default=True, help="Include subgroups")
@click.pass_context
def collect_gitlab(
    ctx: click.Context,
    group: str | None,
    types: tuple[str, ...],
    output: str | None,
    days: int,
    url: str,
    include_subgroups: bool,
) -> None:
    """Collect evidence from GitLab.

    Collects source control, CI/CD, and security evidence from GitLab including
    projects, protected branches, merge requests, pipelines, members, security
    vulnerabilities, audit events, and deploy keys.

    Authentication requires a GitLab personal access token, which can be
    configured via 'attestful configure credentials --platform gitlab' or
    set via the GITLAB_TOKEN environment variable.

    Examples:

        attestful collect gitlab

        attestful collect gitlab --group my-group

        attestful collect gitlab -t projects -t pipelines -t vulnerabilities

        attestful collect gitlab --url https://gitlab.mycompany.com --group internal

        attestful collect gitlab --days 30 -o ./evidence
    """
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.collectors.platforms import GitLabCollector, GitLabCollectorConfig
    from attestful.config import get_credential_store, get_settings
    from attestful.storage import EvidenceStore

    console.print("[bold blue]Collecting GitLab Evidence[/bold blue]")
    console.print(f"  Instance: {url}")
    if group:
        console.print(f"  Group: {group}")
    if types:
        console.print(f"  Evidence types: {', '.join(types)}")
    console.print(f"  History: {days} days")
    console.print()

    # Get credentials from store or environment
    store = get_credential_store()
    cred = store.get_default("gitlab")

    token = ""
    if cred:
        token = cred.data.get("token", "")
    else:
        # Fall back to environment variable
        token = os.environ.get("GITLAB_TOKEN", "")

    if not token:
        console.print("[red]No GitLab credentials configured.[/red]")
        console.print("Run 'attestful configure credentials --platform gitlab' to set up credentials,")
        console.print("or set GITLAB_TOKEN environment variable.")
        return

    # Create collector
    config = GitLabCollectorConfig(
        token=token,
        base_url=url,
        group_id=group or "",
        include_subgroups=include_subgroups,
        days_of_history=days,
    )
    collector = GitLabCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating GitLab credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate GitLab credentials.[/red]")
            console.print("Please verify your personal access token has the required scopes:")
            console.print("  - api (for full access)")
            console.print("  - read_api (for read-only access)")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting GitLab evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
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


@collect.command("jira")
@click.option(
    "--email",
    envvar="JIRA_EMAIL",
    help="Jira user email (Cloud only)",
)
@click.option(
    "--token",
    envvar="JIRA_API_TOKEN",
    help="Jira API token",
)
@click.option(
    "--url",
    envvar="JIRA_URL",
    help="Jira instance URL (e.g., https://company.atlassian.net)",
)
@click.option(
    "--project",
    "-p",
    multiple=True,
    help="Project key(s) to collect from (can be specified multiple times)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice([
        "projects", "issues", "workflows", "users",
        "audit_log", "security_schemes", "permission_schemes", "components"
    ]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.option(
    "--days",
    "-d",
    default=90,
    type=int,
    help="Days of history to collect (default: 90)",
)
@click.option(
    "--cloud/--server",
    default=True,
    help="Jira Cloud (default) or Server/Data Center",
)
@click.pass_context
def collect_jira(
    ctx: click.Context,
    email: str | None,
    token: str | None,
    url: str | None,
    project: tuple[str, ...],
    types: tuple[str, ...],
    output: str | None,
    days: int,
    cloud: bool,
) -> None:
    """Collect evidence from Jira.

    Collects issue tracking and change management evidence including:
    - Projects and project configurations
    - Issues with history (change management)
    - Workflows and statuses
    - Users and permissions
    - Audit log (Cloud only)
    - Security and permission schemes
    - Components

    Authentication:
    - Cloud: email + API token (generate at https://id.atlassian.com/manage-profile/security/api-tokens)
    - Server/Data Center: Personal Access Token

    Examples:
        # Collect from Jira Cloud with all evidence types
        attestful collect jira --email user@company.com --token ATATT... --url https://company.atlassian.net

        # Collect specific evidence types from specific projects
        attestful collect jira --project PROJ1 --project PROJ2 --types issues --types audit_log

        # Collect from Jira Data Center
        attestful collect jira --token PAT... --url https://jira.company.com --server
    """
    from attestful.collectors.platforms.jira import JiraCollector, JiraCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Jira Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not url:
        console.print("[red]Error: Jira URL is required[/red]")
        console.print("Provide via --url or JIRA_URL environment variable")
        return

    if not token:
        console.print("[red]Error: Jira API token is required[/red]")
        console.print("Provide via --token or JIRA_API_TOKEN environment variable")
        return

    if cloud and not email:
        console.print("[red]Error: Email is required for Jira Cloud[/red]")
        console.print("Provide via --email or JIRA_EMAIL environment variable")
        return

    # Create collector config
    config = JiraCollectorConfig(
        email=email or "",
        api_token=token,
        base_url=url,
        project_keys=list(project),
        days_of_history=days,
        is_cloud=cloud,
    )

    collector = JiraCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Jira credentials...", total=None)
        if not collector.validate_credentials():
            console.print("[red]Failed to validate Jira credentials.[/red]")
            if cloud:
                console.print("Please verify your email and API token.")
                console.print("Generate an API token at: https://id.atlassian.com/manage-profile/security/api-tokens")
            else:
                console.print("Please verify your Personal Access Token.")
            return
        progress.update(task, description="[green]Credentials validated[/green]")

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Jira evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("zendesk")
@click.option(
    "--email",
    envvar="ZENDESK_EMAIL",
    help="Zendesk admin email",
)
@click.option(
    "--token",
    envvar="ZENDESK_API_TOKEN",
    help="Zendesk API token",
)
@click.option(
    "--subdomain",
    envvar="ZENDESK_SUBDOMAIN",
    help="Zendesk subdomain (e.g., 'company' for company.zendesk.com)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice([
        "tickets", "ticket_metrics", "users", "groups",
        "organizations", "macros", "triggers", "audit_logs"
    ]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.option(
    "--days",
    "-d",
    default=90,
    type=int,
    help="Days of history to collect (default: 90)",
)
@click.pass_context
def collect_zendesk(
    ctx: click.Context,
    email: str | None,
    token: str | None,
    subdomain: str | None,
    types: tuple[str, ...],
    output: str | None,
    days: int,
) -> None:
    """Collect evidence from Zendesk.

    Collects customer support and incident response evidence including:
    - Support tickets and their lifecycle
    - Ticket SLA and response metrics
    - Agent users and roles
    - Groups and organizations
    - Macros and triggers (automation)
    - Audit logs (Enterprise only)

    Authentication:
    - Requires email and API token
    - Generate API token at Admin > Channels > API

    Examples:
        # Collect all evidence types
        attestful collect zendesk --email admin@company.com --token abc123 --subdomain company

        # Collect specific evidence types
        attestful collect zendesk --subdomain company --types tickets --types users

        # Collect with custom history period
        attestful collect zendesk --subdomain company --days 180
    """
    from attestful.collectors.platforms.zendesk import ZendeskCollector, ZendeskCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Zendesk Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not subdomain:
        console.print("[red]Error: Zendesk subdomain is required[/red]")
        console.print("Provide via --subdomain or ZENDESK_SUBDOMAIN environment variable")
        return

    if not email:
        console.print("[red]Error: Zendesk email is required[/red]")
        console.print("Provide via --email or ZENDESK_EMAIL environment variable")
        return

    if not token:
        console.print("[red]Error: Zendesk API token is required[/red]")
        console.print("Provide via --token or ZENDESK_API_TOKEN environment variable")
        return

    # Create collector config
    config = ZendeskCollectorConfig(
        email=email,
        api_token=token,
        subdomain=subdomain,
        days_of_history=days,
    )

    collector = ZendeskCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Zendesk credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Zendesk credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Zendesk evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("zoom")
@click.option(
    "--account-id",
    envvar="ZOOM_ACCOUNT_ID",
    help="Zoom account ID (Server-to-Server OAuth)",
)
@click.option(
    "--client-id",
    envvar="ZOOM_CLIENT_ID",
    help="Zoom OAuth client ID",
)
@click.option(
    "--client-secret",
    envvar="ZOOM_CLIENT_SECRET",
    help="Zoom OAuth client secret",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice([
        "users", "account_settings", "meeting_settings", "recording_settings",
        "security_settings", "groups", "roles", "signin_signout_activities"
    ]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.option(
    "--days",
    "-d",
    default=90,
    type=int,
    help="Days of history to collect (default: 90)",
)
@click.pass_context
def collect_zoom(
    ctx: click.Context,
    account_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    types: tuple[str, ...],
    output: str | None,
    days: int,
) -> None:
    """Collect evidence from Zoom.

    Collects communications and meeting security evidence including:
    - Users and their roles/permissions
    - Account settings and security configurations
    - Meeting settings and defaults
    - Recording settings
    - SSO and authentication settings
    - Groups and roles
    - Sign-in/sign-out activities

    Authentication:
    - Requires Server-to-Server OAuth app credentials
    - Create app at https://marketplace.zoom.us/develop/create

    Examples:
        # Collect all evidence types
        attestful collect zoom --account-id abc --client-id def --client-secret ghi

        # Collect specific evidence types
        attestful collect zoom --types users --types security_settings

        # Collect with custom history period for activities
        attestful collect zoom --days 30
    """
    from attestful.collectors.platforms.zoom import ZoomCollector, ZoomCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Zoom Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not account_id:
        console.print("[red]Error: Zoom account ID is required[/red]")
        console.print("Provide via --account-id or ZOOM_ACCOUNT_ID environment variable")
        return

    if not client_id:
        console.print("[red]Error: Zoom client ID is required[/red]")
        console.print("Provide via --client-id or ZOOM_CLIENT_ID environment variable")
        return

    if not client_secret:
        console.print("[red]Error: Zoom client secret is required[/red]")
        console.print("Provide via --client-secret or ZOOM_CLIENT_SECRET environment variable")
        return

    # Create collector config
    config = ZoomCollectorConfig(
        account_id=account_id,
        client_id=client_id,
        client_secret=client_secret,
        days_of_history=days,
    )

    collector = ZoomCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Zoom credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Zoom credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Zoom evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("notion")
@click.option(
    "--token",
    envvar="NOTION_API_TOKEN",
    help="Notion Internal Integration Token",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice([
        "pages", "databases", "users", "comments", "permissions", "audit_logs"
    ]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.option(
    "--days",
    "-d",
    default=90,
    type=int,
    help="Days of history to collect (default: 90)",
)
@click.pass_context
def collect_notion(
    ctx: click.Context,
    token: str | None,
    types: tuple[str, ...],
    output: str | None,
    days: int,
) -> None:
    """Collect evidence from Notion.

    Collects documentation and knowledge management evidence including:
    - Pages and their content structure
    - Databases and their schemas
    - Users and workspace members
    - Comments and discussions
    - Page/database permissions
    - Audit logs (Enterprise only)

    Authentication:
    - Requires an Internal Integration Token
    - Create at https://www.notion.so/my-integrations

    Examples:
        # Collect all evidence types
        attestful collect notion --token secret_xxx

        # Collect specific evidence types
        attestful collect notion --types pages --types databases

        # Collect with custom history period
        attestful collect notion --days 180
    """
    from attestful.collectors.platforms.notion import NotionCollector, NotionCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Notion Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not token:
        console.print("[red]Error: Notion API token is required[/red]")
        console.print("Provide via --token or NOTION_API_TOKEN environment variable")
        return

    # Create collector config
    config = NotionCollectorConfig(
        api_token=token,
        days_of_history=days,
    )

    collector = NotionCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Notion credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Notion credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Notion evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("slack")
@click.option(
    "--bot-token",
    envvar="SLACK_BOT_TOKEN",
    help="Slack Bot OAuth Token (xoxb-...)",
)
@click.option(
    "--user-token",
    envvar="SLACK_USER_TOKEN",
    help="Slack User OAuth Token for admin APIs (xoxp-..., optional)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "channels", "user_groups", "team_info", "apps", "access_logs"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history to collect (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_slack(
    ctx: click.Context,
    bot_token: str | None,
    user_token: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Slack workspace.

    Collects communications, workspace security, and collaboration evidence
    for compliance frameworks.

    Required scopes for bot token:
    - users:read, users:read.email - User information
    - channels:read - Channel information
    - usergroups:read - User group information
    - team:read - Team/workspace information

    Optional scopes for admin features (user token):
    - admin.apps:read - Installed apps
    - admin.teams:read - Access logs

    Examples:
        attestful collect slack --bot-token xoxb-...
        attestful collect slack --types users --types channels
        attestful collect slack --days 30
    """
    from attestful.collectors.platforms.slack import SlackCollector, SlackCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Slack Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not bot_token:
        console.print("[red]Error: Slack Bot OAuth Token is required[/red]")
        console.print("Provide via --bot-token or SLACK_BOT_TOKEN environment variable")
        return

    # Create collector config
    config = SlackCollectorConfig(
        bot_token=bot_token,
        user_token=user_token,
        days_of_history=days,
    )

    collector = SlackCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Slack credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Slack credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Slack evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("pagerduty")
@click.option(
    "--token",
    envvar="PAGERDUTY_API_TOKEN",
    help="PagerDuty REST API Token",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["incidents", "services", "schedules", "escalation_policies", "users", "teams", "analytics"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history to collect (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_pagerduty(
    ctx: click.Context,
    token: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from PagerDuty.

    Collects incident management, on-call scheduling, and response evidence
    for compliance frameworks.

    Evidence types:
    - incidents: Incident records and resolution data
    - services: Service definitions and configurations
    - schedules: On-call schedules and coverage
    - escalation_policies: Escalation policy configurations
    - users: User accounts and contact methods
    - teams: Team configurations
    - analytics: Incident response metrics (MTTA, MTTR)

    Examples:
        attestful collect pagerduty --token your-api-token
        attestful collect pagerduty --types incidents --types services
        attestful collect pagerduty --days 30
    """
    from attestful.collectors.platforms.pagerduty import PagerDutyCollector, PagerDutyCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]PagerDuty Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not token:
        console.print("[red]Error: PagerDuty API token is required[/red]")
        console.print("Provide via --token or PAGERDUTY_API_TOKEN environment variable")
        return

    # Create collector config
    config = PagerDutyCollectorConfig(
        api_token=token,
        days_of_history=days,
    )

    collector = PagerDutyCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating PagerDuty credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate PagerDuty credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting PagerDuty evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("terraform-cloud")
@click.option(
    "--token",
    envvar="TFC_TOKEN",
    help="Terraform Cloud API Token",
)
@click.option(
    "--organization",
    "-o",
    envvar="TFC_ORGANIZATION",
    help="Terraform Cloud organization name",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["workspaces", "runs", "state_versions", "policies", "variables", "teams"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history to collect (default: 90)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_terraform_cloud(
    ctx: click.Context,
    token: str | None,
    organization: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Terraform Cloud.

    Collects infrastructure as code, workspace configuration, and run history
    evidence for compliance frameworks.

    Evidence types:
    - workspaces: Workspace configurations and settings
    - runs: Run history and outcomes
    - state_versions: State version history
    - policies: Sentinel policies and policy sets
    - variables: Variable sets and workspace variables
    - teams: Team configurations and access

    Examples:
        attestful collect terraform-cloud --token your-token --organization your-org
        attestful collect terraform-cloud --types workspaces --types runs
        attestful collect terraform-cloud --days 30
    """
    from attestful.collectors.platforms.terraform import TerraformCloudCollector, TerraformCloudCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Terraform Cloud Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not token:
        console.print("[red]Error: Terraform Cloud API token is required[/red]")
        console.print("Provide via --token or TFC_TOKEN environment variable")
        return

    if not organization:
        console.print("[red]Error: Terraform Cloud organization is required[/red]")
        console.print("Provide via --organization or TFC_ORGANIZATION environment variable")
        return

    # Create collector config
    config = TerraformCloudCollectorConfig(
        api_token=token,
        organization=organization,
        days_of_history=days,
    )

    collector = TerraformCloudCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Terraform Cloud credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Terraform Cloud credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Terraform Cloud evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        elif "policy_set_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['policy_set_count']} policy sets)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("slab")
@click.option(
    "--token",
    envvar="SLAB_API_TOKEN",
    help="Slab API Token",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["posts", "topics", "users", "organization"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history to collect (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_slab(
    ctx: click.Context,
    token: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Slab.

    Collects knowledge base, documentation, and internal wiki evidence
    for compliance frameworks.

    Evidence types:
    - posts: Documentation posts and articles
    - topics: Topic/category structure
    - users: User accounts and activity
    - organization: Organization settings

    Examples:
        attestful collect slab --token your-api-token
        attestful collect slab --types posts --types topics
        attestful collect slab --days 30
    """
    from attestful.collectors.platforms.slab import SlabCollector, SlabCollectorConfig
    from attestful.storage.evidence import EvidenceStore

    console.print("[bold blue]Slab Evidence Collection[/bold blue]")
    console.print()

    # Validate required parameters
    if not token:
        console.print("[red]Error: Slab API token is required[/red]")
        console.print("Provide via --token or SLAB_API_TOKEN environment variable")
        return

    # Create collector config
    config = SlabCollectorConfig(
        api_token=token,
        days_of_history=days,
    )

    collector = SlabCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Slab credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Slab credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Slab evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("spotdraft")
@click.option(
    "--api-key",
    envvar="SPOTDRAFT_API_KEY",
    help="SpotDraft API Key",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["contracts", "templates", "approvals", "users", "audit_logs", "folders"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history to collect (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_spotdraft(
    ctx: click.Context,
    api_key: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from SpotDraft.

    Collects contract lifecycle, approvals, and audit evidence
    from SpotDraft contract management platform.

    Example usage:
        attestful collect spotdraft --api-key KEY
        attestful collect spotdraft --types contracts --types approvals
        SPOTDRAFT_API_KEY=key attestful collect spotdraft
    """
    from attestful.collectors.platforms.spotdraft import (
        SpotDraftCollector,
        SpotDraftCollectorConfig,
    )

    if not api_key:
        console.print("[red]Error: SpotDraft API key is required.[/red]")
        console.print("[dim]Set SPOTDRAFT_API_KEY or use --api-key[/dim]")
        return

    config = SpotDraftCollectorConfig(
        api_key=api_key,
        days_of_history=days,
    )

    collector = SpotDraftCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating SpotDraft credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate SpotDraft credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting SpotDraft evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("jamf")
@click.option(
    "--url",
    envvar="JAMF_URL",
    help="Jamf Pro URL (e.g., https://company.jamfcloud.com)",
)
@click.option(
    "--username",
    envvar="JAMF_USERNAME",
    help="Jamf username (for basic auth)",
)
@click.option(
    "--password",
    envvar="JAMF_PASSWORD",
    help="Jamf password (for basic auth)",
)
@click.option(
    "--client-id",
    envvar="JAMF_CLIENT_ID",
    help="Jamf API client ID (for OAuth)",
)
@click.option(
    "--client-secret",
    envvar="JAMF_CLIENT_SECRET",
    help="Jamf API client secret (for OAuth)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["computers", "mobile_devices", "policies", "configuration_profiles", "users", "extension_attributes", "computer_groups"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_jamf(
    ctx: click.Context,
    url: str | None,
    username: str | None,
    password: str | None,
    client_id: str | None,
    client_secret: str | None,
    types: tuple[str, ...],
    output: str | None,
) -> None:
    """Collect evidence from Jamf Pro.

    Collects endpoint management, device inventory, and policy evidence
    from Jamf Pro MDM platform.

    Supports both basic authentication (username/password) and OAuth
    (client_id/client_secret).

    Example usage:
        attestful collect jamf --url https://company.jamfcloud.com --username USER --password PASS
        attestful collect jamf --url URL --client-id ID --client-secret SECRET
        JAMF_URL=url JAMF_USERNAME=user JAMF_PASSWORD=pass attestful collect jamf
    """
    from attestful.collectors.platforms.jamf import (
        JamfCollector,
        JamfCollectorConfig,
    )

    if not url:
        console.print("[red]Error: Jamf URL is required.[/red]")
        console.print("[dim]Set JAMF_URL or use --url[/dim]")
        return

    has_basic_auth = username and password
    has_oauth = client_id and client_secret

    if not has_basic_auth and not has_oauth:
        console.print("[red]Error: Jamf credentials required.[/red]")
        console.print("[dim]Use --username/--password or --client-id/--client-secret[/dim]")
        return

    config = JamfCollectorConfig(
        url=url,
        username=username or "",
        password=password or "",
        client_id=client_id or "",
        client_secret=client_secret or "",
    )

    collector = JamfCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Jamf credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Jamf credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Jamf evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("google-workspace")
@click.option(
    "--credentials-file",
    envvar="GOOGLE_APPLICATION_CREDENTIALS",
    help="Path to service account JSON credentials file",
)
@click.option(
    "--delegated-user",
    envvar="GOOGLE_DELEGATED_USER",
    help="Admin user email to impersonate",
)
@click.option(
    "--customer-id",
    envvar="GOOGLE_CUSTOMER_ID",
    default="my_customer",
    help="Google Workspace customer ID (default: my_customer)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "groups", "devices", "login_activity", "org_units", "tokens", "security_alerts"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history for login activity (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_google_workspace(
    ctx: click.Context,
    credentials_file: str | None,
    delegated_user: str | None,
    customer_id: str,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Google Workspace.

    Collects user, group, device, and security evidence from
    Google Workspace Admin SDK.

    Requires a service account with domain-wide delegation and
    appropriate Admin SDK API scopes enabled.

    Example usage:
        attestful collect google-workspace --credentials-file creds.json --delegated-user admin@example.com
        attestful collect google-workspace --types users --types groups
        GOOGLE_APPLICATION_CREDENTIALS=creds.json GOOGLE_DELEGATED_USER=admin@example.com attestful collect google-workspace
    """
    from attestful.collectors.platforms.google_workspace import (
        GoogleWorkspaceCollector,
        GoogleWorkspaceCollectorConfig,
    )

    if not credentials_file:
        console.print("[red]Error: Google credentials file is required.[/red]")
        console.print("[dim]Set GOOGLE_APPLICATION_CREDENTIALS or use --credentials-file[/dim]")
        return

    if not delegated_user:
        console.print("[red]Error: Delegated admin user email is required.[/red]")
        console.print("[dim]Set GOOGLE_DELEGATED_USER or use --delegated-user[/dim]")
        return

    config = GoogleWorkspaceCollectorConfig(
        credentials_file=credentials_file,
        delegated_user=delegated_user,
        customer_id=customer_id,
        days_of_history=days,
    )

    collector = GoogleWorkspaceCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Google Workspace credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Google Workspace credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Google Workspace evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("snowflake")
@click.option(
    "--account",
    envvar="SNOWFLAKE_ACCOUNT",
    help="Snowflake account identifier (e.g., xy12345.us-east-1)",
)
@click.option(
    "--user",
    envvar="SNOWFLAKE_USER",
    help="Snowflake username",
)
@click.option(
    "--password",
    envvar="SNOWFLAKE_PASSWORD",
    help="Snowflake password",
)
@click.option(
    "--warehouse",
    envvar="SNOWFLAKE_WAREHOUSE",
    help="Default warehouse to use",
)
@click.option(
    "--role",
    envvar="SNOWFLAKE_ROLE",
    help="Role to use for queries",
)
@click.option(
    "--private-key",
    envvar="SNOWFLAKE_PRIVATE_KEY_PATH",
    type=click.Path(exists=True),
    help="Path to private key file for key-pair auth",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "roles", "warehouses", "databases", "access_history", "query_history", "grants", "network_policies"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=30,
    help="Days of history for access/query logs (default: 30)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_snowflake(
    ctx: click.Context,
    account: str | None,
    user: str | None,
    password: str | None,
    warehouse: str | None,
    role: str | None,
    private_key: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Snowflake.

    Collects user, role, warehouse, database, and audit evidence from
    Snowflake data warehouse.

    Supports both password and key-pair authentication.

    Example usage:
        attestful collect snowflake --account xy12345 --user admin --password secret
        attestful collect snowflake --types users --types roles --types grants
        SNOWFLAKE_ACCOUNT=xy12345 SNOWFLAKE_USER=admin attestful collect snowflake
    """
    from attestful.collectors.platforms.snowflake import (
        SnowflakeCollector,
        SnowflakeCollectorConfig,
    )

    if not account:
        console.print("[red]Error: Snowflake account is required.[/red]")
        console.print("[dim]Set SNOWFLAKE_ACCOUNT or use --account[/dim]")
        return

    if not user:
        console.print("[red]Error: Snowflake user is required.[/red]")
        console.print("[dim]Set SNOWFLAKE_USER or use --user[/dim]")
        return

    if not password and not private_key:
        console.print("[red]Error: Either password or private key is required.[/red]")
        console.print("[dim]Set SNOWFLAKE_PASSWORD or use --password or --private-key[/dim]")
        return

    config = SnowflakeCollectorConfig(
        account=account,
        user=user,
        password=password or "",
        warehouse=warehouse or "",
        role=role or "",
        private_key_path=private_key or "",
        days_of_history=days,
    )

    collector = SnowflakeCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Snowflake credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Snowflake credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Snowflake evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("microsoft365")
@click.option(
    "--tenant-id",
    envvar="AZURE_TENANT_ID",
    help="Azure AD tenant ID",
)
@click.option(
    "--client-id",
    envvar="AZURE_CLIENT_ID",
    help="Azure AD application (client) ID",
)
@click.option(
    "--client-secret",
    envvar="AZURE_CLIENT_SECRET",
    help="Azure AD client secret",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "groups", "devices", "sign_ins", "security_alerts", "conditional_access", "directory_roles", "applications"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=30,
    help="Days of history for sign-in logs (default: 30)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_microsoft365(
    ctx: click.Context,
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Microsoft 365.

    Collects user, group, device, and security evidence from
    Microsoft 365 using the Microsoft Graph API.

    Requires an Azure AD app registration with appropriate
    Microsoft Graph API permissions.

    Example usage:
        attestful collect microsoft365 --tenant-id xxx --client-id yyy --client-secret zzz
        attestful collect microsoft365 --types users --types groups --types sign_ins
        AZURE_TENANT_ID=xxx AZURE_CLIENT_ID=yyy AZURE_CLIENT_SECRET=zzz attestful collect microsoft365
    """
    from attestful.collectors.platforms.microsoft365 import (
        Microsoft365Collector,
        Microsoft365CollectorConfig,
    )

    if not tenant_id:
        console.print("[red]Error: Azure tenant ID is required.[/red]")
        console.print("[dim]Set AZURE_TENANT_ID or use --tenant-id[/dim]")
        return

    if not client_id:
        console.print("[red]Error: Azure client ID is required.[/red]")
        console.print("[dim]Set AZURE_CLIENT_ID or use --client-id[/dim]")
        return

    if not client_secret:
        console.print("[red]Error: Azure client secret is required.[/red]")
        console.print("[dim]Set AZURE_CLIENT_SECRET or use --client-secret[/dim]")
        return

    config = Microsoft365CollectorConfig(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        days_of_history=days,
    )

    collector = Microsoft365Collector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Microsoft 365 credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Microsoft 365 credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Microsoft 365 evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("onepassword")
@click.option(
    "--connect-url",
    envvar="OP_CONNECT_URL",
    help="1Password Connect server URL",
)
@click.option(
    "--connect-token",
    envvar="OP_CONNECT_TOKEN",
    help="1Password Connect server token",
)
@click.option(
    "--scim-url",
    envvar="OP_SCIM_URL",
    help="1Password SCIM bridge URL",
)
@click.option(
    "--scim-token",
    envvar="OP_SCIM_TOKEN",
    help="1Password SCIM bearer token",
)
@click.option(
    "--events-token",
    envvar="OP_EVENTS_TOKEN",
    help="1Password Events API token",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "groups", "vaults", "items", "audit_events"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history for audit events (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_onepassword(
    ctx: click.Context,
    connect_url: str | None,
    connect_token: str | None,
    scim_url: str | None,
    scim_token: str | None,
    events_token: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from 1Password.

    Collects password management, secrets, and access evidence from
    1Password using the Connect, SCIM, or Events APIs.

    Supports three APIs:
    - Connect API: For vaults and items (requires Connect server)
    - SCIM API: For users and groups (requires SCIM bridge)
    - Events API: For audit events

    Example usage:
        attestful collect onepassword --connect-url https://connect.company.com --connect-token xxx
        attestful collect onepassword --scim-url https://scim.1password.com/xxx --scim-token yyy
        attestful collect onepassword --events-token zzz
        OP_CONNECT_URL=xxx OP_CONNECT_TOKEN=yyy attestful collect onepassword
    """
    from attestful.collectors.platforms.onepassword import (
        OnePasswordCollector,
        OnePasswordCollectorConfig,
    )

    # Check that at least one API is configured
    has_connect = connect_url and connect_token
    has_scim = scim_url and scim_token
    has_events = events_token

    if not (has_connect or has_scim or has_events):
        console.print("[red]Error: At least one 1Password API must be configured.[/red]")
        console.print("[dim]Options:[/dim]")
        console.print("[dim]  - Connect API: --connect-url and --connect-token (or OP_CONNECT_URL/OP_CONNECT_TOKEN)[/dim]")
        console.print("[dim]  - SCIM API: --scim-url and --scim-token (or OP_SCIM_URL/OP_SCIM_TOKEN)[/dim]")
        console.print("[dim]  - Events API: --events-token (or OP_EVENTS_TOKEN)[/dim]")
        return

    config = OnePasswordCollectorConfig(
        connect_url=connect_url or "",
        connect_token=connect_token or "",
        scim_url=scim_url or "",
        scim_token=scim_token or "",
        events_token=events_token or "",
        days_of_history=days,
    )

    collector = OnePasswordCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating 1Password credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate 1Password credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting 1Password evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("confluence")
@click.option(
    "--url",
    envvar="CONFLUENCE_URL",
    help="Confluence URL (e.g., https://company.atlassian.net)",
)
@click.option(
    "--username",
    envvar="CONFLUENCE_USERNAME",
    help="Confluence username (email for Cloud)",
)
@click.option(
    "--api-token",
    envvar="CONFLUENCE_API_TOKEN",
    help="Confluence API token",
)
@click.option(
    "--personal-access-token",
    envvar="CONFLUENCE_PAT",
    help="Personal access token (for Server/Data Center)",
)
@click.option(
    "--server",
    is_flag=True,
    default=False,
    help="Use Server/Data Center API (default: Cloud)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["spaces", "pages", "users", "groups", "permissions", "audit_logs"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history for audit logs (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_confluence(
    ctx: click.Context,
    url: str | None,
    username: str | None,
    api_token: str | None,
    personal_access_token: str | None,
    server: bool,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Confluence.

    Collects documentation, knowledge management, and policy evidence
    from Atlassian Confluence.

    Supports both Cloud and Server/Data Center deployments.

    Example usage:
        attestful collect confluence --url https://company.atlassian.net --username user@company.com --api-token xxx
        attestful collect confluence --url https://confluence.company.com --personal-access-token xxx --server
        CONFLUENCE_URL=xxx CONFLUENCE_USERNAME=yyy CONFLUENCE_API_TOKEN=zzz attestful collect confluence
    """
    from attestful.collectors.platforms.confluence import (
        ConfluenceCollector,
        ConfluenceCollectorConfig,
    )

    if not url:
        console.print("[red]Error: Confluence URL is required.[/red]")
        console.print("[dim]Set CONFLUENCE_URL or use --url[/dim]")
        return

    # Check authentication
    has_basic_auth = username and api_token
    has_pat = personal_access_token

    if not (has_basic_auth or has_pat):
        console.print("[red]Error: Authentication is required.[/red]")
        console.print("[dim]Options:[/dim]")
        console.print("[dim]  - Basic auth: --username and --api-token (or CONFLUENCE_USERNAME/CONFLUENCE_API_TOKEN)[/dim]")
        console.print("[dim]  - PAT: --personal-access-token (or CONFLUENCE_PAT) with --server flag[/dim]")
        return

    config = ConfluenceCollectorConfig(
        url=url,
        username=username or "",
        api_token=api_token or "",
        personal_access_token=personal_access_token or "",
        is_cloud=not server,
        days_of_history=days,
    )

    collector = ConfluenceCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Confluence credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Confluence credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Confluence evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("linear")
@click.option(
    "--api-key",
    envvar="LINEAR_API_KEY",
    help="Linear API key",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "teams", "projects", "issues", "cycles", "audit_logs"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    default=90,
    help="Days of history for issues and audit logs (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_linear(
    ctx: click.Context,
    api_key: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Linear.

    Collects project management, issue tracking, and team collaboration
    evidence from Linear using the GraphQL API.

    Example usage:
        attestful collect linear --api-key lin_api_xxx
        attestful collect linear --types users --types teams --types issues
        LINEAR_API_KEY=xxx attestful collect linear
    """
    from attestful.collectors.platforms.linear import (
        LinearCollector,
        LinearCollectorConfig,
    )

    if not api_key:
        console.print("[red]Error: Linear API key is required.[/red]")
        console.print("[dim]Set LINEAR_API_KEY or use --api-key[/dim]")
        return

    config = LinearCollectorConfig(
        api_key=api_key,
        days_of_history=days,
    )

    collector = LinearCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Linear credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Linear credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Linear evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("shortcut")
@click.option(
    "--api-token",
    envvar="SHORTCUT_API_TOKEN",
    help="Shortcut API token (or set SHORTCUT_API_TOKEN)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["members", "teams", "projects", "stories", "epics", "iterations", "workflows"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=90,
    help="Days of history to collect for stories",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_shortcut(
    ctx: click.Context,
    api_token: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Shortcut.

    Collects project management, issue tracking, and team collaboration
    evidence from Shortcut (formerly Clubhouse).

    Example usage:
        attestful collect shortcut --api-token xxx-xxx-xxx
        attestful collect shortcut --types members --types projects --types stories
        SHORTCUT_API_TOKEN=xxx attestful collect shortcut
    """
    from attestful.collectors.platforms.shortcut import (
        ShortcutCollector,
        ShortcutCollectorConfig,
    )

    if not api_token:
        console.print("[red]Error: Shortcut API token is required.[/red]")
        console.print("[dim]Set SHORTCUT_API_TOKEN or use --api-token[/dim]")
        return

    config = ShortcutCollectorConfig(
        api_token=api_token,
        days_of_history=days,
    )

    collector = ShortcutCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Shortcut credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Shortcut credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Shortcut evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("asana")
@click.option(
    "--access-token",
    envvar="ASANA_ACCESS_TOKEN",
    help="Asana access token (or set ASANA_ACCESS_TOKEN)",
)
@click.option(
    "--workspace",
    "-w",
    "workspace_gid",
    help="Workspace GID to collect from (default: all workspaces)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "teams", "projects", "tasks", "portfolios", "goals", "workspaces"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=90,
    help="Days of history to collect for tasks",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_asana(
    ctx: click.Context,
    access_token: str | None,
    workspace_gid: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Asana.

    Collects project management, task tracking, and team collaboration
    evidence from Asana.

    Example usage:
        attestful collect asana --access-token 1/1234567890:abcdef
        attestful collect asana --workspace 1234567890
        attestful collect asana --types users --types projects --types tasks
        ASANA_ACCESS_TOKEN=xxx attestful collect asana
    """
    from attestful.collectors.platforms.asana import (
        AsanaCollector,
        AsanaCollectorConfig,
    )

    if not access_token:
        console.print("[red]Error: Asana access token is required.[/red]")
        console.print("[dim]Set ASANA_ACCESS_TOKEN or use --access-token[/dim]")
        return

    config = AsanaCollectorConfig(
        access_token=access_token,
        workspace_gid=workspace_gid or "",
        days_of_history=days,
    )

    collector = AsanaCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Asana credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Asana credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Asana evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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


@collect.command("monday")
@click.option(
    "--api-token",
    envvar="MONDAY_API_TOKEN",
    help="Monday.com API token (or set MONDAY_API_TOKEN)",
)
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["users", "teams", "workspaces", "boards", "items", "updates", "activity_logs"]),
    help="Evidence types to collect (default: all)",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=90,
    help="Days of history to collect",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output directory for evidence",
)
@click.pass_context
def collect_monday(
    ctx: click.Context,
    api_token: str | None,
    types: tuple[str, ...],
    days: int,
    output: str | None,
) -> None:
    """Collect evidence from Monday.com.

    Collects work management, project tracking, and team collaboration
    evidence from Monday.com.

    Example usage:
        attestful collect monday --api-token eyJhbGciOiJIUzI1...
        attestful collect monday --types users --types boards --types items
        MONDAY_API_TOKEN=xxx attestful collect monday
    """
    from attestful.collectors.platforms.monday import (
        MondayCollector,
        MondayCollectorConfig,
    )

    if not api_token:
        console.print("[red]Error: Monday.com API token is required.[/red]")
        console.print("[dim]Set MONDAY_API_TOKEN or use --api-token[/dim]")
        return

    config = MondayCollectorConfig(
        api_token=api_token,
        days_of_history=days,
    )

    collector = MondayCollector(config=config)

    # Validate credentials
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating Monday.com credentials...", total=None)
        try:
            if not collector.validate_credentials():
                console.print("[red]Failed to validate Monday.com credentials.[/red]")
                return
            progress.update(task, description="[green]Credentials validated[/green]")
        except Exception as e:
            console.print(f"[red]Failed to validate credentials: {e}[/red]")
            return

    # Collect evidence
    evidence_types = list(types) if types else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Collecting Monday.com evidence...", total=None)
        try:
            result = collector.collect_evidence(evidence_types=evidence_types)
            progress.update(task, description=f"[green]Collected {len(result.evidence_items)} evidence items[/green]")
        except Exception as e:
            console.print(f"[red]Failed to collect evidence: {e}[/red]")
            return

    # Show what was collected
    console.print()
    console.print("[bold]Evidence Collected:[/bold]")
    for evidence in result.evidence_items:
        count_info = ""
        if "total_count" in evidence.raw_data:
            count_info = f" ({evidence.raw_data['total_count']} items)"
        console.print(f"  - {evidence.evidence_type}{count_info}")

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
        ("kubernetes", "Both", "[green]Available[/green]"),
        ("gitlab", "Both", "[green]Available[/green]"),
        ("jira", "Both", "[green]Available[/green]"),
        ("zendesk", "Both", "[green]Available[/green]"),
        ("zoom", "Both", "[green]Available[/green]"),
        ("notion", "Both", "[green]Available[/green]"),
        ("jamf", "Both", "[green]Available[/green]"),
        ("google-workspace", "Both", "[green]Available[/green]"),
        ("snowflake", "Both", "[green]Available[/green]"),
        ("microsoft365", "Both", "[green]Available[/green]"),
        ("datadog", "Evidence", "[green]Available[/green]"),
        ("pagerduty", "Both", "[green]Available[/green]"),
        ("slack", "Both", "[green]Available[/green]"),
        ("terraform-cloud", "Both", "[green]Available[/green]"),
        ("slab", "Both", "[green]Available[/green]"),
        ("spotdraft", "Both", "[green]Available[/green]"),
        ("onepassword", "Both", "[green]Available[/green]"),
        ("confluence", "Both", "[green]Available[/green]"),
        ("linear", "Both", "[green]Available[/green]"),
        ("shortcut", "Both", "[green]Available[/green]"),
        ("asana", "Both", "[green]Available[/green]"),
        ("monday", "Both", "[green]Available[/green]"),
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


@analyze.command("crosswalk")
@click.option(
    "--source",
    "-s",
    type=click.Choice(["nist-800-53", "soc2", "iso-27001", "hitrust"]),
    required=True,
    help="Source framework",
)
@click.option(
    "--target",
    "-t",
    type=click.Choice(["nist-800-53", "soc2", "iso-27001", "hitrust"]),
    help="Target framework (optional, shows all if not specified)",
)
@click.option(
    "--control",
    "-c",
    help="Specific control ID to map (e.g., AC-1, CC1.1)",
)
@click.option(
    "--strength",
    type=click.Choice(["exact", "strong", "partial", "related", "all"]),
    default="all",
    help="Minimum mapping strength to show",
)
@click.option(
    "--stats",
    is_flag=True,
    help="Show mapping statistics only",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.pass_context
def analyze_crosswalk(
    ctx: click.Context,
    source: str,
    target: str | None,
    control: str | None,
    strength: str,
    stats: bool,
    fmt: str,
) -> None:
    """Cross-framework control mapping.

    Find equivalent controls between compliance frameworks.

    Examples:

        # Find all mappings from a NIST 800-53 control
        attestful analyze crosswalk -s nist-800-53 -c AC-1

        # Find SOC 2 equivalents for an ISO 27001 control
        attestful analyze crosswalk -s iso-27001 -t soc2 -c A.5.1

        # Show only strong/exact mappings
        attestful analyze crosswalk -s soc2 -t hitrust --strength strong

        # View mapping statistics
        attestful analyze crosswalk -s nist-800-53 --stats
    """
    import json as json_module
    from rich.table import Table
    from attestful.analysis import (
        Framework,
        MappingStrength,
        get_crosswalk,
    )

    console.print(f"[bold blue]Cross-Framework Control Mapping[/bold blue]")
    console.print()

    # Get crosswalk instance
    crosswalk = get_crosswalk()

    # Map string to enum
    source_fw = Framework(source)
    target_fw = Framework(target) if target else None

    # Mapping strength filter
    strength_order = [
        MappingStrength.EXACT,
        MappingStrength.STRONG,
        MappingStrength.PARTIAL,
        MappingStrength.RELATED,
    ]
    min_strength_idx = (
        strength_order.index(MappingStrength(strength))
        if strength != "all"
        else len(strength_order)
    )

    if stats:
        # Show mapping statistics
        console.print(f"[bold]Mapping Statistics for {source.upper()}[/bold]")
        console.print()

        # Get all mappings and filter by source framework
        all_mappings = crosswalk.get_all_mappings()
        source_mappings = [m for m in all_mappings if m.source_framework == source_fw]

        # Count by target framework
        framework_counts: dict[str, dict[str, int]] = {}
        source_controls: set[str] = set()
        for mapping in source_mappings:
            source_controls.add(mapping.source_control)
            fw = mapping.target_framework.value
            if fw not in framework_counts:
                framework_counts[fw] = {"total": 0, "controls": set()}
            framework_counts[fw]["total"] += 1
            framework_counts[fw]["controls"].add(mapping.source_control)

        table = Table(title="Coverage by Target Framework")
        table.add_column("Target Framework", style="cyan")
        table.add_column("Source Controls", justify="right")
        table.add_column("Total Mappings", justify="right")
        table.add_column("Avg per Control", justify="right")

        for fw, counts in sorted(framework_counts.items()):
            num_controls = len(counts["controls"])
            avg = counts["total"] / num_controls if num_controls > 0 else 0
            table.add_row(
                fw.upper(),
                str(num_controls),
                str(counts["total"]),
                f"{avg:.1f}",
            )

        console.print(table)
        console.print()

        # Total source controls with mappings
        console.print(f"[dim]Total {source.upper()} controls with mappings: {len(source_controls)}[/dim]")
        console.print(f"[dim]Total mappings from {source.upper()}: {len(source_mappings)}[/dim]")
        return

    if control:
        # Map specific control
        result = crosswalk.get_mappings(source_fw, control)

        if not result.mappings:
            console.print(f"[yellow]No mappings found for {control} in {source.upper()}[/yellow]")
            return

        # Filter by target framework and strength
        filtered_mappings = []
        for mapping in result.mappings:
            if target_fw and mapping.target_framework != target_fw:
                continue
            if strength != "all":
                mapping_idx = strength_order.index(mapping.strength)
                if mapping_idx > min_strength_idx:
                    continue
            filtered_mappings.append(mapping)

        if fmt == "json":
            output = {
                "source_framework": source,
                "source_control": control,
                "mappings": [
                    {
                        "target_framework": m.target_framework.value,
                        "target_control": m.target_control,
                        "strength": m.strength.value,
                        "notes": m.notes,
                    }
                    for m in filtered_mappings
                ],
            }
            console.print(json_module.dumps(output, indent=2))
        else:
            table = Table(title=f"Mappings for {control} ({source.upper()})")
            table.add_column("Target Framework", style="cyan")
            table.add_column("Control ID", style="green")
            table.add_column("Strength", style="magenta")
            table.add_column("Notes", style="dim")

            # Color coding for strength
            strength_colors = {
                MappingStrength.EXACT: "green",
                MappingStrength.STRONG: "blue",
                MappingStrength.PARTIAL: "yellow",
                MappingStrength.RELATED: "dim",
            }

            for mapping in filtered_mappings:
                color = strength_colors.get(mapping.strength, "white")
                table.add_row(
                    mapping.target_framework.value.upper(),
                    mapping.target_control,
                    f"[{color}]{mapping.strength.value}[/{color}]",
                    mapping.notes or "",
                )

            console.print(table)
            console.print()
            console.print(f"[dim]Found {len(filtered_mappings)} mapping(s)[/dim]")
    else:
        # Show all mappings between frameworks
        if not target_fw:
            console.print("[yellow]Specify --target or --control for detailed mappings[/yellow]")
            console.print()
            console.print("Available frameworks:")
            for fw in Framework:
                console.print(f"  • {fw.value}")
            return

        # Get all mappings from source to target
        all_raw_mappings = crosswalk.get_all_mappings()
        filtered_pairs: list[tuple[str, Any]] = []

        for mapping in all_raw_mappings:
            if mapping.source_framework != source_fw:
                continue
            if mapping.target_framework != target_fw:
                continue
            if strength != "all":
                mapping_idx = strength_order.index(mapping.strength)
                if mapping_idx > min_strength_idx:
                    continue
            filtered_pairs.append((mapping.source_control, mapping))

        if fmt == "json":
            output = {
                "source_framework": source,
                "target_framework": target,
                "mappings": [
                    {
                        "source_control": ctrl,
                        "target_control": m.target_control,
                        "strength": m.strength.value,
                        "notes": m.notes,
                    }
                    for ctrl, m in filtered_pairs
                ],
            }
            console.print(json_module.dumps(output, indent=2))
        else:
            table = Table(title=f"Mappings: {source.upper()} → {target.upper()}")
            table.add_column("Source Control", style="cyan")
            table.add_column("Target Control", style="green")
            table.add_column("Strength", style="magenta")

            strength_colors = {
                MappingStrength.EXACT: "green",
                MappingStrength.STRONG: "blue",
                MappingStrength.PARTIAL: "yellow",
                MappingStrength.RELATED: "dim",
            }

            for ctrl_id, mapping in sorted(filtered_pairs, key=lambda x: x[0]):
                color = strength_colors.get(mapping.strength, "white")
                table.add_row(
                    ctrl_id,
                    mapping.target_control,
                    f"[{color}]{mapping.strength.value}[/{color}]",
                )

            console.print(table)
            console.print()
            console.print(f"[dim]Found {len(filtered_pairs)} mapping(s)[/dim]")


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
# Dashboard Commands (Section 14)
# =============================================================================


@cli.group()
@click.pass_context
def dashboard(ctx: click.Context) -> None:
    """Launch and manage the compliance dashboard."""
    pass


@dashboard.command("serve")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8050, type=int, help="Port to run on")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.pass_context
def dashboard_serve(ctx: click.Context, host: str, port: int, debug: bool) -> None:
    """
    Start the interactive dashboard server.

    The dashboard provides:
    - Large hero compliance percentage display
    - Framework selector with category breakdowns
    - Platform status grid showing collection status
    - Light/dark mode toggle
    - Evidence summary statistics

    Requires enterprise extras: pip install 'attestful[enterprise]'
    """
    try:
        from attestful.dashboard import run_dashboard
    except ImportError:
        console.print("[red]Dashboard requires enterprise extras.[/red]")
        console.print("Install with: pip install 'attestful[enterprise]'")
        return

    console.print("[bold blue]Attestful Dashboard[/bold blue]")
    console.print(f"  Starting server on http://{host}:{port}")
    console.print()
    console.print("  Features:")
    console.print("    • Monochrome design with 72px hero compliance percentage")
    console.print("    • Framework selector (SOC 2, NIST CSF, NIST 800-53, ISO 27001, HITRUST)")
    console.print("    • Category breakdown with progress bars")
    console.print("    • Platform status grid with connection indicators")
    console.print("    • Light/dark mode toggle with persistence")
    console.print()
    console.print("  Press Ctrl+C to stop the server")
    console.print()

    run_dashboard(host=host, port=port, debug=debug)


@dashboard.command("export")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="attestful_dashboard.html",
    help="Output HTML file path",
)
@click.pass_context
def dashboard_export(ctx: click.Context, output: str) -> None:
    """
    Export dashboard as static HTML for air-gapped viewing.

    Creates a self-contained HTML file that can be opened in any browser
    without a server. Suitable for offline deployments and sharing.

    The static export includes:
    - All styling bundled inline (no external dependencies)
    - Light/dark mode toggle (persisted in localStorage)
    - Current compliance data snapshot
    - Framework overview for all frameworks
    """
    from attestful.dashboard import export_static_dashboard

    console.print("[bold blue]Exporting Static Dashboard[/bold blue]")
    console.print()

    try:
        result_path = export_static_dashboard(output)
        console.print(f"[green]Dashboard exported to:[/green] {result_path}")
        console.print()
        console.print("Features included:")
        console.print("  • Self-contained HTML (no external dependencies)")
        console.print("  • Light/dark mode toggle")
        console.print("  • Compliance data snapshot")
        console.print("  • Works completely offline")
        console.print()
        console.print(f"Open in browser: file://{result_path.absolute()}")
    except Exception as e:
        console.print(f"[red]Failed to export dashboard: {e}[/red]")


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
# OSCAL Profile Commands
# =============================================================================


@oscal.group()
@click.pass_context
def profile(ctx: click.Context) -> None:
    """Profile operations (control selection and tailoring)."""
    pass


@profile.command("resolve")
@click.argument("profile_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path for resolved catalog")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Output format",
)
@click.pass_context
def profile_resolve(
    ctx: click.Context,
    profile_file: str,
    output: str | None,
    fmt: str,
) -> None:
    """Resolve an OSCAL profile to produce a resolved catalog.

    Takes a profile file and resolves it against its source catalogs,
    applying all imports, merges, and modifications to produce a
    flattened catalog containing only the selected controls.
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.oscal.profile import ProfileResolver, get_profile_summary

    console.print(f"[bold blue]Resolving OSCAL Profile[/bold blue]")
    console.print(f"  Input: {profile_file}")
    console.print()

    resolver = ProfileResolver()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Resolving profile...", total=None)
        try:
            resolved = resolver.resolve_from_file(profile_file)
            progress.update(task, description="[green]Profile resolved[/green]")
        except Exception as e:
            progress.update(task, description="[red]Failed[/red]")
            console.print(f"[red]Error resolving profile: {e}[/red]")
            return

    # Determine output path
    if not output:
        ext = "json" if fmt == "json" else "yaml"
        output = f"resolved_catalog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save the resolved catalog
    catalog = resolved.catalog
    if fmt == "json":
        import orjson
        data = {"catalog": catalog.model_dump(by_alias=True, exclude_none=True, mode="json")}
        output_path.write_text(orjson.dumps(data, option=orjson.OPT_INDENT_2).decode())
    else:
        import yaml
        data = {"catalog": catalog.model_dump(by_alias=True, exclude_none=True, mode="json")}
        output_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    console.print()
    console.print(f"[bold green]Resolved catalog saved to:[/bold green] {output_path}")
    console.print()
    console.print("[bold]Resolution Summary:[/bold]")
    console.print(f"  Source Profile: {resolved.source_profile.metadata.title}")
    console.print(f"  Controls Selected: {resolved.control_count}")
    console.print(f"  Parameters Set: {len(resolved.resolved_parameters)}")

    # Show resolved parameters if any
    if resolved.resolved_parameters:
        console.print()
        console.print("[bold]Resolved Parameters:[/bold]")
        for param_id, value in list(resolved.resolved_parameters.items())[:5]:
            console.print(f"  {param_id}: {value}")
        if len(resolved.resolved_parameters) > 5:
            console.print(f"  ... and {len(resolved.resolved_parameters) - 5} more")


@profile.command("show")
@click.argument("profile_file", type=click.Path(exists=True))
@click.pass_context
def profile_show(ctx: click.Context, profile_file: str) -> None:
    """Display information about an OSCAL profile."""
    from attestful.oscal.profile import ProfileLoader, get_profile_summary

    console.print(f"[bold blue]OSCAL Profile Information[/bold blue]")
    console.print()

    loader = ProfileLoader()
    try:
        profile = loader.load(profile_file)
        summary = get_profile_summary(profile)

        console.print(f"[bold]Title:[/bold] {summary['title']}")
        console.print(f"[bold]UUID:[/bold] {summary['uuid']}")
        console.print(f"[bold]Version:[/bold] {summary['version']}")
        console.print()

        console.print("[bold]Imports:[/bold]")
        for imp in summary["imports"]:
            console.print(f"  Source: {imp['href']}")
            console.print(f"    Include All: {imp['include_all']}")
            console.print(f"    Control Selections: {imp['control_selections']}")
            console.print(f"    Control Exclusions: {imp['control_exclusions']}")

        console.print()
        console.print("[bold]Modifications:[/bold]")
        console.print(f"  Parameter Settings: {summary['modifications']['parameter_settings']}")
        console.print(f"  Control Alterations: {summary['modifications']['alterations']}")

    except Exception as e:
        console.print(f"[red]Failed to load profile: {e}[/red]")


@profile.command("create")
@click.option("--title", "-t", required=True, help="Profile title")
@click.option("--catalog", "-c", required=True, type=click.Path(exists=True), help="Source catalog file")
@click.option("--control", "-C", multiple=True, help="Control IDs to include (can specify multiple)")
@click.option("--include-all", is_flag=True, help="Include all controls from catalog")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Output format",
)
@click.pass_context
def profile_create(
    ctx: click.Context,
    title: str,
    catalog: str,
    control: tuple[str, ...],
    include_all: bool,
    output: str | None,
    fmt: str,
) -> None:
    """Create a new OSCAL profile.

    Creates a profile that selects controls from a source catalog.
    Use --control multiple times to select specific controls, or
    --include-all to include all controls.
    """
    from attestful.oscal.profile import create_profile
    import orjson
    import yaml

    if not include_all and not control:
        console.print("[red]Error: Specify --control or --include-all[/red]")
        return

    console.print(f"[bold blue]Creating OSCAL Profile[/bold blue]")
    console.print(f"  Title: {title}")
    console.print(f"  Source Catalog: {catalog}")
    console.print()

    # Build import configuration
    if include_all:
        imports = [{"href": catalog, "include-all": {}}]
        console.print("  Including: all controls")
    else:
        imports = [{"href": catalog, "include-controls": [{"with-ids": list(control)}]}]
        console.print(f"  Including: {len(control)} controls")

    # Create profile
    profile = create_profile(title=title, imports=imports)

    # Determine output path
    if not output:
        ext = "json" if fmt == "json" else "yaml"
        safe_title = title.lower().replace(" ", "_")[:30]
        output = f"profile_{safe_title}.{ext}"

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save
    data = {"profile": profile.model_dump(by_alias=True, exclude_none=True, mode="json")}
    if fmt == "json":
        output_path.write_text(orjson.dumps(data, option=orjson.OPT_INDENT_2).decode())
    else:
        output_path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    console.print()
    console.print(f"[bold green]Profile saved to:[/bold green] {output_path}")


# =============================================================================
# OSCAL Component Commands
# =============================================================================


@oscal.group()
@click.pass_context
def component(ctx: click.Context) -> None:
    """Component Definition operations."""
    pass


@component.command("generate")
@click.option("--title", "-t", required=True, help="Component definition title")
@click.option("--scan-file", type=click.Path(exists=True), help="JSON file from previous scan")
@click.option("--provider", "-p", type=click.Choice(["aws", "azure", "gcp"]), help="Cloud provider for component grouping")
@click.option("--framework", "-f", "framework", help="Framework to map (e.g., soc2, nist_800_53)")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-F",
    "fmt",
    type=click.Choice(["json", "yaml"]),
    default="json",
    help="Output format",
)
@click.pass_context
def component_generate(
    ctx: click.Context,
    title: str,
    scan_file: str | None,
    provider: str | None,
    framework: str | None,
    output: str | None,
    fmt: str,
) -> None:
    """Generate an OSCAL Component Definition.

    Creates a component definition from scan results, mapping automated
    checks to OSCAL control implementations.
    """
    import json as json_module
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from attestful.oscal.component import (
        ComponentDefinitionGenerator,
        ComponentConfig,
        create_aws_component_definition,
        create_azure_component_definition,
        get_component_definition_summary,
    )
    from attestful.core.models import ComplianceCheck

    console.print(f"[bold blue]Generating OSCAL Component Definition[/bold blue]")
    console.print(f"  Title: {title}")
    if provider:
        console.print(f"  Provider: {provider}")
    if framework:
        console.print(f"  Framework: {framework}")
    console.print()

    checks: list[ComplianceCheck] = []

    # Load checks from scan file if provided
    if scan_file:
        console.print(f"Loading scan results from {scan_file}...")
        try:
            scan_data = json_module.loads(Path(scan_file).read_text())

            for r in scan_data.get("results", []):
                # Extract framework mappings from result
                check_id = r.get("check_id", "")
                mappings: dict[str, list[str]] = {}

                # Try to infer framework mappings
                if "CC" in check_id:
                    mappings["soc2"] = [check_id]

                checks.append(ComplianceCheck(
                    id=check_id,
                    title=r.get("check_title", check_id),
                    description=r.get("message", ""),
                    severity=r.get("severity", "medium"),
                    resource_types=[r.get("resource_type", "unknown")],
                    framework_mappings=mappings,
                ))

            console.print(f"  Loaded {len(checks)} checks from scan results")
        except Exception as e:
            console.print(f"[red]Failed to load scan file: {e}[/red]")
            return

    # Generate component definition
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating component definition...", total=None)

        try:
            if provider == "aws" and checks:
                comp_def = create_aws_component_definition(checks)
            elif provider == "azure" and checks:
                comp_def = create_azure_component_definition(checks)
            else:
                generator = ComponentDefinitionGenerator(title=title)

                if checks:
                    generator.add_component_from_checks(
                        ComponentConfig(
                            title=f"{title} Component",
                            description=f"Control implementations from {len(checks)} checks",
                            type="validation",
                        ),
                        checks=checks,
                        framework=framework,
                    )
                else:
                    # Create empty component
                    generator.add_component(
                        ComponentConfig(
                            title=f"{title} Component",
                            description="Component definition",
                            type="software",
                        )
                    )

                comp_def = generator.generate()

            progress.update(task, description="[green]Component definition generated[/green]")
        except Exception as e:
            progress.update(task, description="[red]Failed[/red]")
            console.print(f"[red]Error generating component definition: {e}[/red]")
            return

    # Determine output path
    if not output:
        ext = "json" if fmt == "json" else "yaml"
        safe_title = title.lower().replace(" ", "_")[:30]
        output = f"component_{safe_title}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save
    import orjson
    import yaml as yaml_module
    data = {"component-definition": comp_def.model_dump(by_alias=True, exclude_none=True, mode="json")}
    if fmt == "json":
        output_path.write_text(orjson.dumps(data, option=orjson.OPT_INDENT_2).decode())
    else:
        output_path.write_text(yaml_module.dump(data, default_flow_style=False, sort_keys=False))

    # Get summary
    summary = get_component_definition_summary(comp_def)

    console.print()
    console.print(f"[bold green]Component Definition saved to:[/bold green] {output_path}")
    console.print()
    console.print("[bold]Summary:[/bold]")
    console.print(f"  Components: {len(summary['components'])}")
    console.print(f"  Total Control Implementations: {summary['total_control_implementations']}")

    if summary['components']:
        console.print()
        console.print("[bold]Components:[/bold]")
        for comp in summary['components'][:5]:
            console.print(f"  - {comp['title']} ({comp['type']}): {comp['control_implementations']} implementations")
        if len(summary['components']) > 5:
            console.print(f"  ... and {len(summary['components']) - 5} more")


@component.command("show")
@click.argument("component_file", type=click.Path(exists=True))
@click.pass_context
def component_show(ctx: click.Context, component_file: str) -> None:
    """Display information about an OSCAL Component Definition."""
    from attestful.oscal.component import ComponentDefinitionLoader, get_component_definition_summary

    console.print(f"[bold blue]OSCAL Component Definition Information[/bold blue]")
    console.print()

    loader = ComponentDefinitionLoader()
    try:
        comp_def = loader.load(component_file)
        summary = get_component_definition_summary(comp_def)

        console.print(f"[bold]Title:[/bold] {summary['title']}")
        console.print(f"[bold]UUID:[/bold] {summary['uuid']}")
        console.print(f"[bold]Version:[/bold] {summary['version']}")
        console.print()
        console.print(f"[bold]Total Components:[/bold] {len(summary['components'])}")
        console.print(f"[bold]Total Control Implementations:[/bold] {summary['total_control_implementations']}")
        console.print(f"[bold]Capabilities:[/bold] {summary['capabilities_count']}")

        if summary['components']:
            console.print()
            console.print("[bold]Components:[/bold]")

            table = Table()
            table.add_column("Title", style="cyan")
            table.add_column("Type", style="white")
            table.add_column("Implementations", style="green", justify="right")

            for comp in summary['components']:
                table.add_row(
                    comp['title'],
                    comp['type'],
                    str(comp['control_implementations']),
                )

            console.print(table)

    except Exception as e:
        console.print(f"[red]Failed to load component definition: {e}[/red]")


@component.command("list-controls")
@click.argument("component_file", type=click.Path(exists=True))
@click.pass_context
def component_list_controls(ctx: click.Context, component_file: str) -> None:
    """List all controls implemented in a Component Definition."""
    from attestful.oscal.component import ComponentDefinitionLoader, ComponentDefinitionIndex

    console.print(f"[bold blue]Controls in Component Definition[/bold blue]")
    console.print()

    loader = ComponentDefinitionLoader()
    try:
        comp_def = loader.load(component_file)
        index = ComponentDefinitionIndex(comp_def)

        control_ids = sorted(index.list_control_ids())

        console.print(f"[bold]Total Controls:[/bold] {len(control_ids)}")
        console.print()

        table = Table()
        table.add_column("Control ID", style="cyan")
        table.add_column("Implementing Components", style="white")

        for control_id in control_ids:
            implementations = index.get_implementations_for_control(control_id)
            components = [comp.title for comp, _ in implementations]
            table.add_row(control_id, ", ".join(components))

        console.print(table)

    except Exception as e:
        console.print(f"[red]Failed to load component definition: {e}[/red]")


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
@click.option("--provider", "-p", type=click.Choice(["aws", "azure"]), default="aws", help="Cloud provider")
@click.option("--output", "-o", type=click.Path(), help="Output file for remediation plan")
@click.pass_context
def remediate_plan(
    ctx: click.Context,
    scan_file: str,
    framework: str,
    provider: str,
    output: str | None,
) -> None:
    """Create a remediation plan from scan results."""
    import json as json_module
    from attestful.remediation import (
        RemediationPlan,
        RiskLevel,
        get_remediation_action,
        get_azure_remediation_action,
    )

    console.print(f"[bold blue]Creating Remediation Plan[/bold blue]")
    console.print(f"  Provider: {provider}")
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
        action = None
        if provider == "aws":
            action = get_remediation_action(
                check_id=result["check_id"],
                resource_id=result["resource_id"],
                resource_data={"type": result["resource_type"]},
                dry_run=True,  # Plan is always dry-run
            )
        elif provider == "azure":
            # Extract Azure-specific metadata
            resource_data = result.get("resource_data", {})
            if not resource_data:
                resource_data = {"type": result["resource_type"], "name": result["resource_id"]}
            # Try to extract resource group from resource_id or metadata
            resource_group = resource_data.get("resource_group") or resource_data.get("metadata", {}).get("resource_group")
            subscription_id = resource_data.get("subscription_id") or scan_data.get("metadata", {}).get("subscription_id", "")

            action = get_azure_remediation_action(
                check_id=result["check_id"],
                resource_id=result["resource_id"],
                resource_data=resource_data,
                subscription_id=subscription_id,
                resource_group=resource_group,
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
@click.option("--provider", "-p", type=click.Choice(["aws", "azure"]), default="aws", help="Cloud provider")
@click.option("--region", "-r", default="us-east-1", help="AWS region")
@click.option("--subscription-id", help="Azure subscription ID (can also use AZURE_SUBSCRIPTION_ID env var)")
@click.pass_context
def remediate_run(
    ctx: click.Context,
    scan_file: str,
    dry_run: bool,
    auto_approve: bool,
    max_risk: str,
    skip_high_risk: bool,
    output: str | None,
    provider: str,
    region: str,
    subscription_id: str | None,
) -> None:
    """Execute remediation for failed compliance checks."""
    import asyncio
    import json as json_module
    import os
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from attestful.remediation import (
        RemediationEngine,
        RemediationPlan,
        RemediationStatus,
        RiskLevel,
        get_remediation_action,
        get_azure_remediation_action,
    )

    console.print(f"[bold blue]{'[DRY RUN] ' if dry_run else ''}Executing Remediation[/bold blue]")
    console.print(f"  Provider: {provider}")
    console.print(f"  Max Risk Level: {max_risk}")
    console.print(f"  Skip High Risk: {skip_high_risk}")
    console.print(f"  Auto Approve: {auto_approve}")
    console.print()

    # Get Azure subscription ID from env or parameter
    azure_subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if provider == "azure" and not azure_subscription_id:
        console.print("[yellow]Warning: No Azure subscription ID provided. Some remediations may fail.[/yellow]")
        console.print("[dim]Set AZURE_SUBSCRIPTION_ID env var or use --subscription-id[/dim]")
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
        action = None
        if provider == "aws":
            action = get_remediation_action(
                check_id=result["check_id"],
                resource_id=result["resource_id"],
                resource_data={"type": result["resource_type"], "name": result["resource_id"]},
                region=region,
                dry_run=dry_run,
            )
        elif provider == "azure":
            # Extract Azure-specific metadata
            resource_data = result.get("resource_data", {})
            if not resource_data:
                resource_data = {"type": result["resource_type"], "name": result["resource_id"]}
            # Try to extract resource group from resource_id or metadata
            resource_group = resource_data.get("resource_group") or resource_data.get("metadata", {}).get("resource_group")
            sub_id = resource_data.get("subscription_id") or azure_subscription_id or scan_data.get("metadata", {}).get("subscription_id", "")

            action = get_azure_remediation_action(
                check_id=result["check_id"],
                resource_id=result["resource_id"],
                resource_data=resource_data,
                subscription_id=sub_id,
                resource_group=resource_group,
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
@click.option("--provider", "-p", type=click.Choice(["aws", "azure", "all"]), default="all", help="Filter by cloud provider")
@click.pass_context
def remediate_list(ctx: click.Context, provider: str) -> None:
    """List available remediation actions."""
    from attestful.remediation import REMEDIATION_REGISTRY, AZURE_REMEDIATION_REGISTRY, RiskLevel

    # Action metadata for display (service, description, risk)
    action_info = {
        # AWS Actions
        "EnableS3BucketVersioningAction": ("AWS", "S3", "Enable versioning on S3 bucket", RiskLevel.LOW),
        "EnableS3BucketEncryptionAction": ("AWS", "S3", "Enable default encryption on S3 bucket", RiskLevel.LOW),
        "BlockS3PublicAccessAction": ("AWS", "S3", "Block public access on S3 bucket", RiskLevel.MEDIUM),
        "UpdateIAMPasswordPolicyAction": ("AWS", "IAM", "Update IAM password policy", RiskLevel.MEDIUM),
        "EnableCloudTrailLogValidationAction": ("AWS", "CloudTrail", "Enable log file validation", RiskLevel.LOW),
        "RemoveOpenSSHAccessAction": ("AWS", "EC2/SG", "Remove unrestricted SSH access", RiskLevel.HIGH),
        "EnableKMSKeyRotationAction": ("AWS", "KMS", "Enable automatic key rotation", RiskLevel.LOW),
        # Azure Actions
        "BlockStoragePublicAccessAction": ("Azure", "Storage", "Block public access on storage account", RiskLevel.MEDIUM),
        "EnableStorageSoftDeleteAction": ("Azure", "Storage", "Enable blob soft delete", RiskLevel.LOW),
        "EnableKeyVaultPurgeProtectionAction": ("Azure", "KeyVault", "Enable purge protection (irreversible)", RiskLevel.HIGH),
        "EnableKeyVaultSoftDeleteAction": ("Azure", "KeyVault", "Enable soft delete", RiskLevel.MEDIUM),
        "EnableSQLAuditingAction": ("Azure", "SQL", "Enable SQL Server auditing", RiskLevel.LOW),
        "EnableSQLThreatDetectionAction": ("Azure", "SQL", "Enable Advanced Threat Protection", RiskLevel.LOW),
        "RemoveNSGOpenSSHAction": ("Azure", "NSG", "Remove unrestricted SSH access", RiskLevel.HIGH),
        "RemoveNSGOpenRDPAction": ("Azure", "NSG", "Remove unrestricted RDP access", RiskLevel.HIGH),
    }

    table = Table(title="Available Remediation Actions")
    table.add_column("Provider", style="magenta", width=8)
    table.add_column("Service", style="cyan", width=10)
    table.add_column("Action", style="white", width=40)
    table.add_column("Risk Level", style="yellow", width=12)
    table.add_column("Check IDs", style="green", width=35)

    # Collect all registries to display
    registries_to_show = []
    if provider in ["aws", "all"]:
        registries_to_show.append(("AWS", REMEDIATION_REGISTRY))
    if provider in ["azure", "all"]:
        registries_to_show.append(("Azure", AZURE_REMEDIATION_REGISTRY))

    for provider_name, registry in registries_to_show:
        # Group by action class
        action_check_map: dict[type, list[str]] = {}
        for check_id, action_class in registry.items():
            if action_class not in action_check_map:
                action_check_map[action_class] = []
            action_check_map[action_class].append(check_id)

        for action_class, check_ids in action_check_map.items():
            class_name = action_class.__name__
            if class_name in action_info:
                prov, service, description, risk = action_info[class_name]
                risk_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "red bold"}
                risk_display = f"[{risk_color[risk.value]}]{risk.value.upper()}[/{risk_color[risk.value]}]"

                checks_str = check_ids[0]
                if len(check_ids) > 1:
                    checks_str += f" (+{len(check_ids) - 1} more)"

                table.add_row(prov, service, description, risk_display, checks_str)

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
