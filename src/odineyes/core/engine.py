"""
Odineyes - Core Scan Engine
Orchestrates parallel multicloud security checks with progress tracking.
"""

import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box

from odineyes.core.check_registry import CheckRegistry
from odineyes.core.risk_engine import RiskEngine
from odineyes.core.agentless_scanner import AgentlessScanner
from odineyes.core.graph_engine import GraphEngine
from odineyes.core.suppression_engine import SuppressionEngine
from odineyes.core.config_manager import ConfigManager
from odineyes.utils.logger import setup_logger

logger = setup_logger()


class ScanEngine:
    """
    Orchestrates security checks across multiple cloud providers.
    Supports parallel execution, compliance mapping, and risk scoring.
    """
    
    def __init__(
        self,
        providers: List[str],
        regions: List[str] = None,
        profile: str = "default",
        subscription_id: str = None,
        project_id: str = None,
        categories: List[str] = None,
        check_ids: List[str] = None,
        excluded_checks: List[str] = None,
        severities: List[str] = None,
        compliance_frameworks: List[str] = None,
        parallel: bool = True,
        threads: int = 10,
        verbose: bool = False,
        tags_filter: Dict[str, str] = None,
        risk_threshold: Optional[float] = None,
        target_resource_id: Optional[str] = None,
        console: Console = None,
    ):
        self.providers = providers
        self.regions = regions or []
        self.profile = profile
        self.subscription_id = subscription_id
        self.project_id = project_id
        self.categories = categories or ["all"]
        self.check_ids = check_ids or []
        self.excluded_checks = excluded_checks or []
        self.severities = severities or ["critical", "high", "medium", "low"]
        self.compliance_frameworks = compliance_frameworks or []
        self.parallel = parallel
        self.threads = threads
        self.verbose = verbose
        self.tags_filter = tags_filter or {}
        self.risk_threshold = risk_threshold
        self.target_resource_id = target_resource_id
        self.console = console or Console()
        
        self.registry = CheckRegistry()
        self.risk_engine = RiskEngine()
        self._lock = threading.Lock()
        self._findings = []
        self._stats = {
            "checks_run": 0,
            "checks_passed": 0,
            "checks_failed": 0,
            "checks_error": 0,
            "findings_passed": 0,
            "findings_failed": 0,
        }

    def run(self, quiet: bool = False) -> Dict[str, Any]:
        """Execute all resolved checks and return aggregated results."""
        scan_start = datetime.now(timezone.utc)
        
        # Resolve checks to run
        checks = self.registry.resolve_checks(
            self.providers, self.categories, 
            self.check_ids, self.excluded_checks
        )
        
        # Filter by severity
        if "all" not in self.severities:
            checks = [c for c in checks if c.severity in self.severities]
        
        if not checks:
            self.console.print("[yellow]No checks matched the given filters.[/yellow]")
            return {}

        if not quiet:
            target_msg = f" targeted at [yellow]{self.target_resource_id}[/yellow]" if self.target_resource_id else ""
            self.console.print(f"[bold blue]🔍 Running [cyan]{len(checks)}[/cyan] security checks across "
                             f"[cyan]{', '.join(p.upper() for p in self.providers)}[/cyan]{target_msg}...[/bold blue]\n")

        # Execute checks
        if self.parallel and len(checks) > 1:
            self._run_parallel(checks, quiet)
        else:
            self._run_sequential(checks, quiet)

        # Execute agentless scanning if compute category is enabled
        if "all" in self.categories or "compute" in self.categories:
            config = ConfigManager()._config
            scanner_id = config.get("aws", {}).get("scanner_instance_id")
            if scanner_id:
                agentless_scanner = AgentlessScanner(self.profile, self.regions[0] if self.regions else "us-east-1", scanner_id)
                self._process_result(agentless_scanner.run())

        findings = self._findings.copy()

        # Target Resource Filter (Real-Time Event Driven Mode)
        if self.target_resource_id:
            findings = [f for f in findings if f.get("resource_id", "").startswith(self.target_resource_id) or f.get("resource_id") == "root"]
            if not quiet:
                self.console.print(f"[dim]Filtered down to {len(findings)} findings for target {self.target_resource_id}[/dim]")

        # Suppression Filter
        suppression_engine = SuppressionEngine()
        findings = suppression_engine.filter(findings)

        # Graph Engine Correlation
        graph_engine = GraphEngine()
        toxic_findings = graph_engine.correlate(findings)
        if toxic_findings:
            if not quiet:
                self.console.print(f"[bold red]☢ Generated {len(toxic_findings)} Toxic Combinations![/bold red]")
            findings.extend(toxic_findings)

        # Post-process: risk scoring, compliance mapping
        risk_score = self.risk_engine.calculate_overall_score(findings)
        
        if self.compliance_frameworks:
            findings = self._map_compliance(findings)
        
        if self.risk_threshold is not None:
            findings = [f for f in findings if f.get("risk_score", 0) >= self.risk_threshold]

        scan_end = datetime.now(timezone.utc)
        
        results = {
            "scan_metadata": {
                "tool": "Odineyes",
                "version": "2.0.0",
                "scan_id": f"CS-{int(time.time())}",
                "start_time": scan_start.isoformat(),
                "end_time": scan_end.isoformat(),
                "duration_seconds": (scan_end - scan_start).total_seconds(),
                "providers": self.providers,
                "regions": self.regions,
                "checks_run": self._stats["checks_run"],
                "compliance_frameworks": self.compliance_frameworks,
            },
            "summary": {
                "total_checks": self._stats["checks_run"],
                "total_findings": self._stats["findings_passed"] + self._stats["findings_failed"],
                "passed": self._stats["findings_passed"],
                "failed": self._stats["findings_failed"],
                "errors": self._stats["checks_error"],
                "pass_rate": round(
                    (self._stats["findings_passed"] / max(
                        self._stats["findings_passed"] + self._stats["findings_failed"], 1
                    )) * 100, 2
                ),
                "by_severity": self._count_by_severity(findings),
                "by_provider": self._count_by_provider(findings),
                "by_category": self._count_by_category(findings),
            },
            "risk_score": risk_score,
            "risk_level": self.risk_engine.score_to_level(risk_score),
            "findings": findings,
        }

        if not quiet:
            self._display_live_findings_table(findings[:10])  # Show top 10 critical findings

        return results

    def _run_parallel(self, checks: list, quiet: bool):
        """Execute checks in parallel using ThreadPoolExecutor."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            disable=quiet,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(checks))
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._execute_check, check): check 
                          for check in checks}
                
                for future in as_completed(futures):
                    check = futures[future]
                    try:
                        result = future.result(timeout=30)
                        self._process_result(result)
                    except Exception as e:
                        logger.debug(f"Check {check.check_id} failed: {e}")
                        with self._lock:
                            self._stats["checks_error"] += 1
                    finally:
                        progress.advance(task)
                        progress.update(task, description=f"[cyan]Checked: {check.check_id}")

    def _run_sequential(self, checks: list, quiet: bool):
        """Execute checks sequentially."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            disable=quiet,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(checks))
            for check in checks:
                try:
                    result = self._execute_check(check)
                    self._process_result(result)
                except Exception as e:
                    logger.debug(f"Check {check.check_id} error: {e}")
                    self._stats["checks_error"] += 1
                finally:
                    progress.advance(task)

    def _execute_check(self, check) -> List[Dict]:
        """Execute a single check and return findings."""
        ctx = self._build_context(check)
        return check.execute(ctx)

    def _build_context(self, check) -> Dict[str, Any]:
        """Build execution context for a check."""
        return {
            "provider": check.provider,
            "regions": self.regions,
            "profile": self.profile,
            "subscription_id": self.subscription_id,
            "project_id": self.project_id,
            "tags_filter": self.tags_filter,
            "verbose": self.verbose,
        }

    def _process_result(self, findings: List[Dict]):
        """Thread-safe result accumulation."""
        with self._lock:
            self._stats["checks_run"] += 1
            for f in findings:
                # Enrich each finding with risk score
                f["risk_score"] = self.risk_engine.calculate_finding_score(f)
                
                if f.get("status") == "pass":
                    self._stats["findings_passed"] += 1
                else:
                    self._stats["findings_failed"] += 1
                
                self._findings.append(f)

    def _map_compliance(self, findings: List[Dict]) -> List[Dict]:
        """Map findings to compliance framework controls."""
        from odineyes.core.compliance_mapper import ComplianceMapper
        mapper = ComplianceMapper()
        for finding in findings:
            finding["compliance_mappings"] = mapper.map_finding(
                finding, self.compliance_frameworks
            )
        return findings

    def _display_live_findings_table(self, findings: List[Dict]):
        """Display top findings in a rich table."""
        critical_findings = [f for f in findings if f.get("status") != "pass"][:15]
        if not critical_findings:
            return

        table = Table(
            title="[bold red]⚠ Top Security Findings[/bold red]",
            box=box.ROUNDED, border_style="red",
            show_lines=True
        )
        table.add_column("Check ID", style="cyan", no_wrap=True, width=14)
        table.add_column("Resource", style="white", width=30)
        table.add_column("Severity", width=10)
        table.add_column("Finding", style="white", width=45)
        table.add_column("Risk", justify="right", width=6)

        sev_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green",
        }

        for f in critical_findings:
            sev = f.get("severity", "low").lower()
            color = sev_colors.get(sev, "white")
            table.add_row(
                f.get("check_id", "N/A"),
                (f.get("resource_id", "N/A") or "N/A")[:30],
                f"[{color}]{sev.upper()}[/{color}]",
                (f.get("message", "") or "")[:45],
                f"[{color}]{f.get('risk_score', 'N/A')}[/{color}]",
            )

        self.console.print()
        self.console.print(table)

    def _count_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            if f.get("status") != "pass":
                sev = f.get("severity", "informational").lower()
                counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_provider(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            if f.get("status") != "pass":
                provider = f.get("provider", "unknown")
                counts[provider] = counts.get(provider, 0) + 1
        return counts

    def _count_by_category(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            if f.get("status") != "pass":
                cat = f.get("category", "unknown")
                counts[cat] = counts.get(cat, 0) + 1
        return counts
