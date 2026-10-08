#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║          Odineyes - Multicloud Security & GRC Platform       ║
║          Enterprise-grade CLI for AWS | Azure | GCP               ║
╚═══════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import click
import json
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from odineyes.core.engine import ScanEngine
from odineyes.core.config_manager import ConfigManager
from odineyes.core.report_builder import ReportBuilder
from odineyes.core.compliance_mapper import ComplianceMapper
from odineyes.core.event_listener import EventListener
from odineyes.sensor.runtime_agent import RuntimeSensor
from odineyes.utils.banner import print_banner
from odineyes.utils.logger import setup_logger

console = Console()
logger = setup_logger()

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], max_content_width=120)


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.version_option(version="2.0.0", prog_name="Odineyes")
@click.pass_context
def cli(ctx):
    """
    \b
    ╔═══════════════════════════════════════════════════════╗
    ║   Odineyes v2.0 - Multicloud GRC Security Tool   ║
    ║   AWS | Azure | GCP | Compliance | Risk Scoring       ║
    ╚═══════════════════════════════════════════════════════╝

    A next-generation multicloud security & governance platform.

    \b
    Quick Start:
      odineyes scan --provider aws --compliance CIS
      odineyes scan --provider azure --subscription-id <id>
      odineyes scan --provider gcp --project-id <id>
      odineyes scan --all-providers
      odineyes list-checks
      odineyes compliance --framework CIS --provider aws
    """
    if ctx.invoked_subcommand is None:
        print_banner(console)
        click.echo(ctx.get_help())


@cli.command("scan")
@click.option("--provider", "-p",
              type=click.Choice(["aws", "azure", "gcp", "all"], case_sensitive=False),
              default="aws", show_default=True,
              help="Cloud provider to scan")
@click.option("--all-providers", "-A", is_flag=True, default=False,
              help="Scan all configured cloud providers")
@click.option("--region", "-r", multiple=True,
              help="AWS region(s) to scan (repeatable: -r us-east-1 -r eu-west-1)")
@click.option("--subscription-id", "-s",
              help="Azure subscription ID")
@click.option("--project-id", "-g",
              help="GCP project ID")
@click.option("--profile", default="default", show_default=True,
              help="AWS CLI profile name")
@click.option("--checks", "-c", multiple=True,
              help="Specific check IDs to run (repeatable)")
@click.option("--category", multiple=True,
              type=click.Choice(["iam", "network", "storage", "compute",
                                 "logging", "encryption", "all"]),
              default=["all"], show_default=True,
              help="Check categories to run (repeatable)")
@click.option("--severity", multiple=True,
              type=click.Choice(["critical", "high", "medium", "low", "informational"]),
              default=["critical", "high", "medium", "low"],
              help="Severity levels to include")
@click.option("--compliance", multiple=True,
              type=click.Choice(["CIS", "SOC2", "HIPAA", "PCI-DSS",
                                 "NIST", "ISO27001", "GDPR", "FedRAMP"]),
              help="Compliance frameworks to map (repeatable)")
@click.option("--output", "-o", default="./odineyes-report",
              help="Output path prefix (without extension)")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "html", "csv", "all"]),
              default="html", show_default=True,
              help="Report output format")
@click.option("--parallel/--no-parallel", default=True, show_default=True,
              help="Run checks in parallel")
@click.option("--threads", default=10, show_default=True,
              help="Number of parallel threads")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress progress output")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose/debug output")
@click.option("--fail-on",
              type=click.Choice(["critical", "high", "medium"]),
              help="Exit non-zero if findings at this severity exist (CI/CD)")
@click.option("--dry-run", is_flag=True, default=False,
              help="List checks that would run without executing them")
@click.option("--config", "config_file", default=None,
              help="Path to Odineyes config YAML")
@click.option("--tag", multiple=True,
              help="Filter resources by tag key=value (repeatable)")
@click.option("--exclude-check", multiple=True,
              help="Exclude specific check IDs (repeatable)")
@click.option("--risk-threshold", default=None, type=float,
              help="Minimum risk score (0-10) to report findings")
@click.option("--daemon", is_flag=True, default=False,
              help="Run continuously in the background")
@click.option("--interval", default=3600, type=int,
              help="Scan interval in seconds for daemon mode")
def scan(provider, all_providers, region, subscription_id, project_id, profile,
         checks, category, severity, compliance, output, output_format,
         parallel, threads, quiet, verbose, fail_on, dry_run, config_file,
         tag, exclude_check, risk_threshold, daemon, interval):
    """
    Run security and compliance scans across cloud providers.

    \b
    Examples:
      odineyes scan --provider aws --compliance CIS
      odineyes scan --provider aws -r us-east-1 -r eu-west-1 --format json
      odineyes scan --provider azure --subscription-id abc123 --compliance SOC2
      odineyes scan --all-providers --compliance CIS --format html
      odineyes scan --provider aws --fail-on critical --quiet
      odineyes scan --provider aws --category iam --category encryption
      odineyes scan --provider aws --dry-run
    """
    if not quiet:
        print_banner(console)

    config = ConfigManager(config_file)

    providers_to_scan = []
    if all_providers or provider == "all":
        providers_to_scan = config.get_all_providers()
    else:
        providers_to_scan = [provider]

    regions = list(region) if region else config.get_default_regions(provider)
    categories = list(category)
    severities = list(severity)
    compliance_frameworks = list(compliance)
    check_ids = list(checks)
    excluded_checks = list(exclude_check)
    tags_filter = dict(t.split("=", 1) for t in tag if "=" in t)

    if not quiet:
        cfg_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        cfg_table.add_column("Key", style="bold cyan", no_wrap=True)
        cfg_table.add_column("Value", style="white")
        cfg_table.add_row("Provider(s)", ", ".join(p.upper() for p in providers_to_scan))
        cfg_table.add_row("Categories", ", ".join(categories))
        cfg_table.add_row("Severities", ", ".join(severities))
        cfg_table.add_row("Compliance", ", ".join(compliance_frameworks) or "None")
        cfg_table.add_row("Output", f"{output_format.upper()} → {output}")
        cfg_table.add_row("Parallel", f"{'Yes' if parallel else 'No'} ({threads} threads)")
        if regions:
            cfg_table.add_row("Regions", ", ".join(regions[:5]) + ("..." if len(regions) > 5 else ""))
        console.print(Panel(cfg_table, title="[bold blue]Scan Configuration[/bold blue]",
                            border_style="blue", padding=(1, 2)))
        console.print()

    if dry_run:
        _show_dry_run(providers_to_scan, categories, check_ids, excluded_checks, console)
        return

    engine = ScanEngine(
        providers=providers_to_scan,
        regions=regions,
        profile=profile,
        subscription_id=subscription_id,
        project_id=project_id,
        categories=categories,
        check_ids=check_ids,
        excluded_checks=excluded_checks,
        severities=severities,
        compliance_frameworks=compliance_frameworks,
        parallel=parallel,
        threads=threads,
        verbose=verbose,
        tags_filter=tags_filter,
        risk_threshold=risk_threshold,
        console=console,
    )

    start_time = time.time()
    
    if not daemon:
        results = engine.run(quiet=quiet)
        elapsed = time.time() - start_time
    else:
        console.print(f"[bold magenta]🔄 Starting Daemon Mode (Interval: {interval}s)[/bold magenta]")
        prev_score = -1.0
        prev_criticals = -1
        
        try:
            while True:
                console.print(f"\n[dim]--- Daemon Scan Started at {time.strftime('%X')} ---[/dim]")
                results = engine.run(quiet=True)
                
                score = results.get("risk_score", 0.0)
                findings = results.get("findings", [])
                criticals = len([f for f in findings if f.get("status") == "fail" and f.get("severity") == "critical"])
                
                alert_triggered = False
                if prev_score != -1.0:
                    if score > prev_score:
                        console.print(f"\n[bold red blink]🚨 ALERT: Risk score increased from {prev_score} to {score}![/bold red blink]")
                        alert_triggered = True
                    if criticals > prev_criticals:
                        console.print(f"\n[bold red blink]🚨 ALERT: New critical findings detected! (Total: {criticals})[/bold red blink]")
                        alert_triggered = True
                
                if not alert_triggered:
                    console.print(f"[green]✓ Scan complete. Score: {score} | Criticals: {criticals}. No new risks detected.[/green]")
                    
                prev_score = score
                prev_criticals = criticals
                
                # Reset engine stats for next run
                engine._stats = {k: 0 for k in engine._stats}
                engine._findings = []
                
                console.print(f"[dim]Sleeping for {interval}s...[/dim]")
                time.sleep(interval)
        except KeyboardInterrupt:
            console.print("\n[yellow]Daemon stopped by user.[/yellow]")
            return
            
    if not results:
        console.print("[yellow]⚠  No results returned. Check credentials and configuration.[/yellow]")
        sys.exit(2)

    if not quiet:
        console.print("\n[bold blue]📊 Generating reports...[/bold blue]")

    builder = ReportBuilder(results, compliance_frameworks)
    formats = ["json", "html", "csv"] if output_format == "all" else [output_format]

    generated = []
    for fmt in formats:
        path = builder.generate(fmt, output)
        generated.append(path)
        if not quiet:
            console.print(f"  [green]✓[/green] {fmt.upper()}: [cyan]{path}[/cyan]")

    _print_summary(results, elapsed, generated, console, quiet)

    if fail_on:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        threshold = order.get(fail_on, 0)
        for f in results.get("findings", []):
            if order.get(f.get("severity", "").lower(), 0) >= threshold \
               and f.get("status") != "pass":
                if not quiet:
                    console.print(f"\n[bold red]✗ Pipeline FAILED:[/bold red] "
                                  f"{fail_on.upper()}+ findings detected.")
                sys.exit(1)

    if not quiet:
        console.print("\n[bold green]✓ Scan complete![/bold green]")


@cli.command("listen")
@click.option("--queue-url", default=None,
              help="Optional SQS Queue URL for sub-second EventBridge monitoring")
@click.option("--provider", default="aws", show_default=True)
def listen(queue_url, provider):
    """
    Continuous Event-Driven Monitoring.
    Polls real AWS CloudTrail events using Boto3 (or EventBridge SQS for sub-second latency) and executes targeted scans.
    """
    print_banner(console)
    listener = EventListener(queue_url=queue_url)

    try:
        for event in listener.listen():
            resource_id = event.get("resource_id")
            event_name = event.get("event_name")
            user = event.get("user")
            
            console.print(f"\n[bold magenta]⚡ Event Detected:[/bold magenta] {event_name} by {user}")
            console.print(f"[dim]Triggering targeted sub-second scan on resource: {resource_id}[/dim]")
            
            # Run targeted scan
            engine = ScanEngine(
                providers=[provider],
                target_resource_id=resource_id,
                console=console
            )
            
            start = time.time()
            results = engine.run(quiet=True)
            elapsed = time.time() - start
            
            # Check results for issues with this resource
            findings = results.get("findings", [])
            failed = [f for f in findings if f.get("status") == "fail"]
            
            if failed:
                console.print(f"[bold red blink]🚨 ALERT:[/bold red blink] Resource {resource_id} has {len(failed)} misconfigurations!")
                for f in failed:
                    console.print(f"   - [{f.get('severity').upper()}] {f.get('message')}")
            else:
                console.print(f"[bold green]✓[/bold green] Resource {resource_id} is secure. ({elapsed:.2f}s)")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Listener stopped by user.[/yellow]")
        sys.exit(0)


@cli.command("run-sensor")
@click.option("--hub-url", default="sqs://odineyes-hub",
              help="URL of the central Odineyes hub to send telemetry to")
def run_sensor(hub_url):
    """
    Deploys a lightweight runtime sensor to the local workload.
    Hooks into local system logs/eBPF to detect anomalies in real-time.
    """
    print_banner(console)
    sensor = RuntimeSensor(hub_url=hub_url)
    sensor.start()


@cli.command("list-checks")
@click.option("--provider", "-p",
              type=click.Choice(["aws", "azure", "gcp", "all"]),
              default="all", show_default=True)
@click.option("--category", "-c",
              type=click.Choice(["iam", "network", "storage", "compute",
                                 "logging", "encryption", "all"]),
              default="all", show_default=True)
@click.option("--severity", "-s",
              type=click.Choice(["critical", "high", "medium", "low",
                                 "informational", "all"]),
              default="all", show_default=True)
@click.option("--compliance", multiple=True,
              type=click.Choice(["CIS", "SOC2", "HIPAA", "PCI-DSS",
                                 "NIST", "ISO27001", "GDPR", "FedRAMP"]))
@click.option("--search", help="Search checks by keyword")
def list_checks(provider, category, severity, compliance, search):
    """
    List all available security checks with metadata.

    \b
    Examples:
      odineyes list-checks
      odineyes list-checks --provider aws --category iam
      odineyes list-checks --severity critical
      odineyes list-checks --compliance CIS
      odineyes list-checks --search bucket
    """
    from odineyes.core.check_registry import CheckRegistry
    registry = CheckRegistry()
    registry.display_checks(provider, category, severity, list(compliance), search, console)


@cli.command("compliance")
@click.option("--framework", "-f", required=True,
              type=click.Choice(["CIS", "SOC2", "HIPAA", "PCI-DSS",
                                 "NIST", "ISO27001", "GDPR", "FedRAMP"]),
              help="Compliance framework to evaluate")
@click.option("--provider", "-p",
              type=click.Choice(["aws", "azure", "gcp"]),
              default="aws", show_default=True)
@click.option("--output", "-o", default=None,
              help="Save output to file (JSON)")
@click.option("--format", "-f2", "output_format",
              type=click.Choice(["table", "json", "html"]),
              default="table", show_default=True)
def compliance(framework, provider, output, output_format):
    """
    Show compliance framework control mappings.

    \b
    Examples:
      odineyes compliance --framework CIS --provider aws
      odineyes compliance --framework SOC2 --provider azure
      odineyes compliance --framework HIPAA --output hipaa.json
    """
    print_banner(console)
    mapper = ComplianceMapper()
    mapper.display_framework(framework, provider, output_format, output, console)


@cli.command("report")
@click.option("--input", "-i", "input_file", required=True,
              help="JSON results file from a previous scan")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["html", "csv", "json"]),
              default="html", show_default=True)
@click.option("--output", "-o", default="odineyes-report",
              help="Output file path prefix")
@click.option("--compliance", multiple=True,
              type=click.Choice(["CIS", "SOC2", "HIPAA", "PCI-DSS",
                                 "NIST", "ISO27001", "GDPR", "FedRAMP"]))
def report(input_file, output_format, output, compliance):
    """
    Generate reports from a previous scan's JSON output.

    \b
    Examples:
      odineyes report --input results.json --format html
      odineyes report --input results.json --format csv --output my-report
    """
    print_banner(console)
    try:
        with open(input_file) as f:
            results = json.load(f)
        builder = ReportBuilder(results, list(compliance))
        path = builder.generate(output_format, output)
        console.print(f"[green]✓ Report generated:[/green] [cyan]{path}[/cyan]")
    except FileNotFoundError:
        console.print(f"[red]✗ File not found:[/red] {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON:[/red] {e}")
        sys.exit(1)


@cli.command("risk-score")
@click.option("--input", "-i", "input_file", required=True,
              help="JSON results file from a scan")
@click.option("--framework", default="CVSS",
              type=click.Choice(["CVSS", "DREAD", "FAIR"]),
              help="Risk scoring framework")
def risk_score(input_file, framework):
    """
    Calculate and display risk scores from scan findings.

    \b
    Examples:
      odineyes risk-score --input results.json
      odineyes risk-score --input results.json --framework DREAD
    """
    from odineyes.core.risk_engine import RiskEngine
    try:
        with open(input_file) as f:
            results = json.load(f)
        engine = RiskEngine(framework)
        engine.display_scores(results, console)
    except FileNotFoundError:
        console.print(f"[red]✗ File not found: {input_file}[/red]")
        sys.exit(1)


@cli.command("inventory")
@click.option("--provider", "-p",
              type=click.Choice(["aws", "azure", "gcp"]),
              default="aws", show_default=True)
@click.option("--region", multiple=True)
@click.option("--resource-type", multiple=True,
              help="Filter by resource type (e.g. s3, ec2, iam)")
@click.option("--output", "-o", default=None,
              help="Save inventory JSON to file")
def inventory(provider, region, resource_type, output):
    """
    Enumerate and inventory cloud resources.

    \b
    Examples:
      odineyes inventory --provider aws --region us-east-1
      odineyes inventory --provider azure
      odineyes inventory --provider aws --output inventory.json
    """
    from odineyes.core.inventory_engine import InventoryEngine
    inv = InventoryEngine(provider, list(region), list(resource_type))
    inv.run(output, console)


@cli.command("configure")
@click.option("--provider", "-p",
              type=click.Choice(["aws", "azure", "gcp"]),
              required=True)
@click.option("--profile", default=None, help="AWS CLI profile name")
@click.option("--region", multiple=True, help="Default region(s)")
@click.option("--subscription-id", help="Azure subscription ID")
@click.option("--project-id", help="GCP project ID")
@click.option("--show", is_flag=True, default=False,
              help="Show current configuration")
def configure(provider, profile, region, subscription_id, project_id, show):
    """
    Configure cloud provider credentials and defaults.

    \b
    Examples:
      odineyes configure --provider aws --profile prod --region us-east-1
      odineyes configure --provider azure --subscription-id abc123
      odineyes configure --provider gcp --project-id my-project
      odineyes configure --provider aws --show
    """
    config = ConfigManager()
    if show:
        config.display(provider, console)
    else:
        config.set_provider(provider, profile=profile, regions=list(region),
                            subscription_id=subscription_id, project_id=project_id)
        console.print(f"[green]✓ {provider.upper()} configuration saved.[/green]")


# ── Helpers ───────────────────────────────────────────────────

def _show_dry_run(providers, categories, check_ids, excluded_checks, console):
    from odineyes.core.check_registry import CheckRegistry
    registry = CheckRegistry()
    checks = registry.resolve_checks(providers, categories, check_ids, excluded_checks)

    table = Table(title="[bold yellow]Dry Run — Checks That Would Execute[/bold yellow]",
                  box=box.ROUNDED, border_style="yellow")
    table.add_column("Check ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Provider", style="blue")
    table.add_column("Category", style="magenta")
    table.add_column("Severity")

    sev_colors = {"critical": "red", "high": "orange3",
                  "medium": "yellow", "low": "green"}
    for c in checks:
        col = sev_colors.get(c.severity, "white")
        table.add_row(c.check_id, c.name, c.provider.upper(),
                      c.category, f"[{col}]{c.severity.upper()}[/{col}]")

    console.print(table)
    console.print(f"\n[bold]Total: [cyan]{len(checks)}[/cyan] checks would run[/bold]")


def _print_summary(results, elapsed, generated, console, quiet):
    if quiet:
        return
    findings = results.get("findings", [])
    sev_counts = results.get("summary", {}).get("by_severity", {})
    passed = results.get("summary", {}).get("passed", 0)
    total = results.get("summary", {}).get("total_checks", 0)
    pass_rate = results.get("summary", {}).get("pass_rate", 0)
    risk_score = results.get("risk_score", 0)
    risk_level = results.get("risk_level", "UNKNOWN")

    console.print()
    sev_table = Table(title="[bold]Scan Results Summary[/bold]",
                      box=box.ROUNDED, border_style="green")
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    sev_table.add_column("Bar", no_wrap=True)

    for label, color, key in [
        ("CRITICAL", "red", "critical"),
        ("HIGH", "orange3", "high"),
        ("MEDIUM", "yellow", "medium"),
        ("LOW", "green", "low"),
        ("PASS", "bright_green", None),
    ]:
        count = passed if key is None else sev_counts.get(key, 0)
        bar = "█" * min(count, 40)
        sev_table.add_row(f"[{color}]{label}[/{color}]",
                          f"[{color}]{count}[/{color}]",
                          f"[{color}]{bar}[/{color}]")
    console.print(sev_table)

    level_color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
                   "LOW": "green", "MINIMAL": "bright_green"}.get(risk_level, "white")
    stats = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    stats.add_column("K", style="bold cyan")
    stats.add_column("V")
    stats.add_row("Total Checks", str(total))
    stats.add_row("Pass Rate", f"{'[green]' if pass_rate >= 80 else '[yellow]'}{pass_rate:.1f}%[/]")
    stats.add_row("Risk Score", f"[{level_color}]{risk_score} / 100  ({risk_level})[/{level_color}]")
    stats.add_row("Duration", f"{elapsed:.1f}s")
    console.print(Panel(stats, title="[bold]Statistics[/bold]", border_style="blue"))


if __name__ == "__main__":
    cli()
