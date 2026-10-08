"""
Odineyes - Real-Time Compliance Monitoring Module
Provides continuous, real-time security and compliance monitoring across multi-cloud environments.
Implements drift detection, continuous scanning, and real-time alerting.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn

from odineyes.core.engine import ScanEngine
from odineyes.core.compliance_mapper import FRAMEWORKS
from odineyes.core.risk_engine import RiskEngine


class MonitorStatus(Enum):
    """Real-time monitoring status states."""
    IDLE = "idle"
    SCANNING = "scanning"
    ALERTING = "alerting"
    DRIFT_DETECTED = "drift_detected"
    COMPLIANT = "compliant"


@dataclass
class RealTimeFinding:
    """Real-time security finding with drift tracking."""
    check_id: str
    check_name: str
    category: str
    status: str  # pass, fail, info, skip
    severity: str
    compliance_frameworks: List[str]
    risk_score: float
    drift_detected: bool = False
    drift_timestamp: Optional[datetime] = None
    previous_state: Optional[str] = None
    current_value: Optional[Any] = None
    expected_value: Optional[Any] = None
    message: str = ""
    resource_arn: Optional[str] = None
    cloud_provider: str = "aws"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for API serialization."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "compliance_frameworks": self.compliance_frameworks,
            "risk_score": self.risk_score,
            "drift_detected": self.drift_detected,
            "drift_timestamp": self.drift_timestamp.isoformat() if self.drift_timestamp else None,
            "previous_state": self.previous_state,
            "current_value": json.dumps(self.current_value) if self.current_value else None,
            "expected_value": json.dumps(self.expected_value) if self.expected_value else None,
            "message": self.message,
            "resource_arn": self.resource_arn,
            "cloud_provider": self.cloud_provider,
        }


@dataclass
class ComplianceSnapshot:
    """Point-in-time compliance snapshot."""
    timestamp: datetime
    provider: str
    framework: str
    version: str
    total_checks: int
    passing_checks: int
    failing_checks: int
    info_checks: int
    skip_checks: int
    overall_score: float
    risk_level: str
    drift_events: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert snapshot to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "provider": self.provider,
            "framework": self.framework,
            "version": self.version,
            "total_checks": self.total_checks,
            "passing_checks": self.passing_checks,
            "failing_checks": self.failing_checks,
            "info_checks": self.info_checks,
            "skip_checks": self.skip_checks,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "drift_events": self.drift_events,
        }


class RealTimeMonitor:
    """
    Real-time compliance monitoring engine.
    
    Provides continuous monitoring with:
    - Drift detection between scan cycles
    - Real-time alerting on security events
    - Compliance score tracking over time
    - Multi-cloud aggregation (AWS | Azure | GCP)
    """
    
    def __init__(
        self,
        scan_engine: ScanEngine,
        risk_engine: RiskEngine = None,
        console: Optional[Console] = None,
        poll_interval_seconds: int = 60,
    ):
        self.scan_engine = scan_engine
        self.risk_engine = risk_engine or RiskEngine()
        self.console = console or Console()
        self.poll_interval = poll_interval_seconds
        
        # State management
        self._findings: Dict[str, RealTimeFinding] = {}
        self._snapshots: List[ComplianceSnapshot] = []
        self._monitoring_active = False
        self._last_scan_time: Optional[datetime] = None
        self._baseline_finding_ids: set = set()
        
        # Callbacks for real-time events
        self._on_drift_detected: Optional[Callable[[RealTimeFinding], Awaitable[None]]] = None
        self._on_alert: Optional[Callable[[RealTimeFinding], Awaitable[None]]] = None
        self._on_compliance_change: Optional[Callable[[ComplianceSnapshot], Awaitable[None]]] = None
        
        # Cloud-specific collectors (initialized by cloud providers)
        self._collectors: Dict[str, Any] = {}
    
    def register_collector(self, provider: str, collector):
        """Register a cloud provider collector."""
        self._collectors[provider.lower()] = collector
    
    def on_drift_detected(self, callback: Callable[[RealTimeFinding], Awaitable[None]]):
        """Register drift detection callback."""
        self._on_drift_detected = callback
    
    def on_alert(self, callback: Callable[[RealTimeFinding], Awaitable[None]]):
        """Register alert callback."""
        self._on_alert = callback
    
    def on_compliance_change(self, callback: Callable[[ComplianceSnapshot], Awaitable[None]]):
        """Register compliance change callback."""
        self._on_compliance_change = callback
    
    async def take_baseline_snapshot(self, provider: str = "aws") -> ComplianceSnapshot:
        """
        Take initial baseline snapshot for drift detection.
        
        Args:
            provider: Cloud provider (aws, azure, gcp)
            
        Returns:
            Baseline compliance snapshot
        """
        self.console.print("[yellow]Taking baseline snapshot for drift detection...[/yellow]")
        
        # Get current findings from the scan engine
        results = await self.scan_engine.run_scan(provider=provider)
        
        # Convert findings to RealTimeFinding objects
        for finding in results.get("findings", []):
            finding_id = f"{finding['resource_arn']}:{finding['check_id']}"
            self._baseline_finding_ids.add(finding_id)
            
            realtime_finding = RealTimeFinding(
                check_id=finding["check_id"],
                check_name=finding.get("check_name", ""),
                category=finding.get("category", "unknown"),
                status=finding["status"],
                severity=finding.get("severity", "low"),
                compliance_frameworks=finding.get("compliance_frameworks", []),
                risk_score=finding.get("risk_score", 0.0) or self.risk_engine.calculate_finding_score(finding),
                resource_arn=finding.get("resource_arn"),
                cloud_provider=provider,
            )
            self._findings[finding_id] = realtime_finding
        
        # Create baseline snapshot
        total = len(self._baseline_finding_ids)
        passing = sum(1 for f in self._findings.values() if f.status == "pass")
        failing = sum(1 for f in self._findings.values() if f.status not in ["pass", "skip"])
        
        snapshot = ComplianceSnapshot(
            timestamp=datetime.now(),
            provider=provider,
            framework="CIS",
            version="1.5.0",
            total_checks=total,
            passing_checks=passing,
            failing_checks=failing,
            info_checks=sum(1 for f in self._findings.values() if f.status == "info"),
            skip_checks=sum(1 for f in self._findings.values() if f.status == "skip"),
            overall_score=self.risk_engine.calculate_overall_score(list(self._findings.values())),
            risk_level=self.risk_engine.score_to_level(self.risk_engine.calculate_overall_score(list(self._findings.values()))),
        )
        
        self._snapshots.append(snapshot)
        self.console.print(f"[green]Baseline snapshot taken: {passing}/{total} checks passing[/green]")
        
        return snapshot
    
    async def detect_drift(self, provider: str = "aws") -> List[RealTimeFinding]:
        """
        Detect configuration drift since baseline.
        
        Compares current state against baseline to identify:
        - New violations (new failing checks)
        - Remediated issues (new passing checks)
        - State changes (pass→fail or fail→pass)
        
        Args:
            provider: Cloud provider
            
        Returns:
            List of drift-affected findings
        """
        if not self._baseline_finding_ids:
            self.console.print("[yellow]No baseline established. Run take_baseline_snapshot() first.[/yellow]")
            return []
        
        # Take current snapshot
        results = await self.scan_engine.run_scan(provider=provider)
        
        drift_findings = []
        
        for finding in results.get("findings", []):
            finding_id = f"{finding['resource_arn']}:{finding['check_id']}"
            
            # Check if this is a new resource
            if finding_id not in self._baseline_finding_ids:
                realtime_finding = RealTimeFinding(
                    check_id=finding["check_id"],
                    check_name=finding.get("check_name", ""),
                    category=finding.get("category", "unknown"),
                    status=finding["status"],
                    severity=finding.get("severity", "low"),
                    compliance_frameworks=finding.get("compliance_frameworks", []),
                    risk_score=finding.get("risk_score", 0.0) or self.risk_engine.calculate_finding_score(finding),
                    resource_arn=finding.get("resource_arn"),
                    cloud_provider=provider,
                )
                drift_findings.append(realtime_finding)
                continue
            
            # Get baseline finding
            baseline = self._findings[finding_id]
            
            # Compare states
            if baseline.status != finding["status"]:
                realtime_finding = RealTimeFinding(
                    check_id=finding["check_id"],
                    check_name=finding.get("check_name", ""),
                    category=finding.get("category", "unknown"),
                    status=finding["status"],
                    severity=finding.get("severity", "low"),
                    compliance_frameworks=finding.get("compliance_frameworks", []),
                    risk_score=finding.get("risk_score", 0.0) or self.risk_engine.calculate_finding_score(finding),
                    drift_detected=True,
                    drift_timestamp=datetime.now(),
                    previous_state=baseline.status,
                    current_value=finding["status"],
                    expected_value=baseline.status if baseline.status == "pass" else finding["status"],
                    message=f"State changed from {baseline.status} to {finding['status']}",
                    resource_arn=finding.get("resource_arn"),
                    cloud_provider=provider,
                )
                
                # Determine drift direction
                if baseline.status == "pass" and finding["status"] not in ["pass", "skip"]:
                    realtime_finding.message += " (COMPLIANCE REGRESSION)"
                elif baseline.status not in ["pass", "skip"] and finding["status"] == "pass":
                    realtime_finding.message += " (COMPLIANCE REMEDIATED)"
                
                drift_findings.append(realtime_finding)
        
        # Update findings with current state
        for finding in results.get("findings", []):
            finding_id = f"{finding['resource_arn']}:{finding['check_id']}"
            if finding_id in self._findings:
                existing = self._findings[finding_id]
                if existing.status != finding["status"]:
                    # Update with new state
                    self._findings[finding_id] = RealTimeFinding(
                        check_id=finding["check_id"],
                        check_name=finding.get("check_name", ""),
                        category=finding.get("category", "unknown"),
                        status=finding["status"],
                        severity=finding.get("severity", "low"),
                        compliance_frameworks=finding.get("compliance_frameworks", []),
                        risk_score=finding.get("risk_score", 0.0) or self.risk_engine.calculate_finding_score(finding),
                        resource_arn=finding.get("resource_arn"),
                        cloud_provider=provider,
                    )
        
        self._last_scan_time = datetime.now()
        
        # Notify listeners of drift events
        for finding in drift_findings:
            if self._on_drift_detected:
                await self._on_drift_detected(finding)
        
        return drift_findings
    
    async def run_continuous_monitoring(
        self, 
        providers: List[str] = ["aws"],
        duration_minutes: Optional[int] = None,
        snapshot_interval_seconds: int = 300
    ):
        """
        Run continuous monitoring with periodic snapshots.
        
        Args:
            providers: Cloud providers to monitor
            duration_minutes: How long to run (None for indefinite)
            snapshot_interval_seconds: How often to take compliance snapshots
        """
        self._monitoring_active = True
        
        self.console.print(
            Panel(
                f"[green]Starting continuous monitoring[/green]\n"
                f"Providers: {', '.join(providers)}\n"
                f"Snapshot interval: {snapshot_interval_seconds}s",
                title="[bold]Real-Time Compliance Monitor[/bold]",
                border_style="green"
            )
        )
        
        # First, take baseline snapshots for all providers
        for provider in providers:
            await self.take_baseline_snapshot(provider)
        
        # Main monitoring loop
        with Live(
            "[yellow]Monitoring...[/yellow]",
            console=self.console,
            refresh_per_second=2
        ) as live:
            
            while self._monitoring_active:
                current_time = datetime.now()
                
                if duration_minutes:
                    elapsed = (current_time - self._last_scan_time).total_seconds() / 60
                    if elapsed >= duration_minutes:
                        self.console.print("[yellow]Monitoring duration reached. Stopping.[/yellow]")
                        break
                
                # Take periodic snapshots
                for provider in providers:
                    try:
                        drift = await self.detect_drift(provider)
                        
                        if drift:
                            status = MonitorStatus.DRIFT_DETECTED
                            live.update(f"[bold yellow]DRIFT DETECTED on {provider}[/bold yellow]\n" + 
                                      f"Found {len(drift)} configuration changes")
                            
                            # Display drift summary
                            self._display_drift_summary(drift, provider)
                            
                    except Exception as e:
                        self.console.print(f"[red]Error monitoring {provider}: {e}[/red]")
                
                # Update progress display
                if self._snapshots:
                    latest = self._snapshots[-1]
                    status = MonitorStatus.COMPLIANT if latest.overall_score < 20 else MonitorStatus.SCANNING
                    
                    table = Table(title="Compliance Status")
                    table.add_column("Metric", style="cyan")
                    table.add_column("Value", justify="right")
                    
                    table.add_row("Score", f"{latest.overall_score:.1f}/100")
                    table.add_row("Risk Level", latest.risk_level)
                    table.add_row("Passing", f"{latest.passing_checks}/{latest.total_checks}")
                    table.add_row("Failing", str(latest.failing_checks))
                    
                    live.update(f"[bold green]Score: {latest.overall_score:.1f}/100[/bold green]\n" +
                              f"[bold yellow]Risk: {latest.risk_level}[/bold yellow]\n" +
                              f"[green]Passing: {latest.passing_checks}/{latest.total_checks}[/green]\n" +
                              f"[red]Failing: {latest.failing_checks}[/red]")
                
                # Wait for next iteration
                await asyncio.sleep(self.poll_interval)
        
        self.console.print("\n[bold green]Continuous monitoring stopped.[/green]")
    
    def _display_drift_summary(self, drift_findings: List[RealTimeFinding], provider: str):
        """Display a summary of detected drift."""
        # Categorize drift by type
        regressions = [f for f in drift_findings if f.previous_state == "pass"]
        remediations = [f for f in drift_findings if f.previous_state not in ["pass", "skip"] and f.status == "pass"]
        new_resources = [f for f in drift_findings if f.resource_arn and 
                        f.check_id not in self._baseline_finding_ids]
        
        # Create summary table
        table = Table(title=f"Drift Summary - {provider}", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Details", style="dim")
        
        if regressions:
            critical = sum(1 for f in regressions if f.severity in ["critical", "high"])
            medium = sum(1 for f in regressions if f.severity == "medium")
            low = sum(1 for f in regressions if f.severity == "low")
            
            table.add_row("⚠️ Compliance Regressions", str(len(regressions)),
                         f"Critical: {critical}, High: {medium}, Low: {low}")
        
        if remediations:
            table.add_row("✅ Remediated Issues", str(len(remediations)), "Configuration improved")
        
        if new_resources:
            table.add_row("➕ New Resources", str(len(new_resources)), 
                         f"New checks: {len([f for f in new_resources if not f.compliance_frameworks])}")
        
        if drift_findings:
            self.console.print(table)
            
            # Show top critical findings
            critical_findings = [f for f in drift_findings 
                                if f.severity in ["critical", "high"] and f.drift_detected]
            
            if critical_findings:
                table2 = Table(title="Critical Drift Details", box=box.ROUNDED)
                table2.add_column("Check ID", style="yellow")
                table2.add_column("Status Change", style="red")
                table2.add_column("Risk Score", justify="right")
                
                for f in critical_findings[:5]:  # Top 5
                    table2.add_row(
                        f.check_id,
                        f"→ {f.status.upper()}" if f.previous_state else f"{f.status.upper()}",
                        str(f.risk_score)
                    )
                
                self.console.print(table2)
    
    async def run_once(self, provider: str = "aws") -> ComplianceSnapshot:
        """
        Run a single scan and return compliance snapshot.
        
        Args:
            provider: Cloud provider to scan
            
        Returns:
            Compliance snapshot for this scan
        """
        results = await self.scan_engine.run_scan(provider=provider)
        
        # Process findings
        total = len(results.get("findings", []))
        passing = sum(1 for f in results["findings"] if f["status"] == "pass")
        failing = sum(1 for f in results["findings"] if f["status"] not in ["pass", "skip"])
        
        snapshot = ComplianceSnapshot(
            timestamp=datetime.now(),
            provider=provider,
            framework="CIS",
            version="1.5.0",
            total_checks=total,
            passing_checks=passing,
            failing_checks=failing,
            info_checks=sum(1 for f in results["findings"] if f["status"] == "info"),
            skip_checks=sum(1 for f in results["findings"] if f["status"] == "skip"),
            overall_score=self.risk_engine.calculate_overall_score(results.get("findings", [])),
            risk_level=self.risk_engine.score_to_level(self.risk_engine.calculate_overall_score(results.get("findings", []))),
        )
        
        self._snapshots.append(snapshot)
        
        return snapshot
    
    def get_current_findings(self, provider: str = "aws") -> List[Dict[str, Any]]:
        """Get current findings for a provider."""
        findings = []
        for finding in self._findings.values():
            if finding.cloud_provider == provider:
                findings.append(finding.to_dict())
        return findings
    
    def get_compliance_history(self, provider: str = "aws") -> List[Dict[str, Any]]:
        """Get compliance history for a provider."""
        return [s.to_dict() for s in self._snapshots if s.provider == provider]
    
    def get_drift_findings(self, provider: str = "aws") -> List[Dict[str, Any]]:
        """Get all findings with drift detected."""
        return [f.to_dict() for f in self._findings.values() 
                if f.drift_detected and f.cloud_provider == provider]
    
    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self._monitoring_active = False
    
    async def send_alert(self, finding: RealTimeFinding):
        """Send real-time alert for critical finding."""
        if self._on_alert:
            await self._on_alert(finding)
        
        # Also print to console for immediate visibility
        alert_message = (
            f"[bold red]🚨 REAL-TIME ALERT[/bold red]\n\n"
            f"Check ID: [yellow]{finding.check_id}[/yellow]\n"
            f"Resource: [cyan]{finding.resource_arn or 'N/A'}[/cyan]\n"
            f"Status: [red]{finding.status.upper()}[/red]\n"
            f"Severity: [bold]{finding.severity.upper()}[/bold]\n"
            f"Risk Score: [magenta]{finding.risk_score:.1f}[/magenta]\n"
            f"Message: [white]{finding.message or finding.current_value or 'No additional info'}[/white]"
        )
        
        if finding.drift_detected:
            alert_message += f"\nDrift Detected: [yellow]Previous: {finding.previous_state} → Current: {finding.status}[/yellow]"
        
        self.console.print(Panel(alert_message, border_style="red", title="Real-Time Alert"))


class ComplianceDashboard:
    """
    Real-time compliance dashboard for monitoring multiple providers.
    
    Provides aggregated views and multi-cloud comparison.
    """
    
    def __init__(self, monitor: RealTimeMonitor):
        self.monitor = monitor
        self.console = Console()
    
    def display_dashboard(self) -> None:
        """Display real-time compliance dashboard."""
        if not self.monitor._snapshots:
            self.console.print("[yellow]No snapshots available. Run a scan first.[/yellow]")
            return
        
        # Aggregate across all providers and frameworks
        latest_snapshots = {}
        for snapshot in reversed(self.monitor._snapshots):
            key = f"{snapshot.provider}:{snapshot.framework}"
            if key not in latest_snapshots or snapshot.timestamp > latest_snapshots[key].timestamp:
                latest_snapshots[key] = snapshot
        
        if not latest_snapshots:
            self.console.print("[yellow]No snapshots available.[/yellow]")
            return
        
        # Create dashboard table
        table = Table(title="Multi-Cloud Compliance Dashboard", box=box.ROUNDED)
        table.add_column("Provider", style="cyan")
        table.add_column("Framework", style="green")
        table.add_column("Score", justify="right")
        table.add_column("Risk Level", style="yellow")
        table.add_column("Passing", justify="right")
        table.add_column("Failing", justify="right", style="red")
        
        for key, snapshot in sorted(latest_snapshots.items(), 
                                    key=lambda x: x[0].split(":")[0]):
            provider, framework = key.split(":", 1)
            score_color = "green" if snapshot.overall_score < 20 else ("yellow" if snapshot.overall_score < 60 else "red")
            
            table.add_row(
                provider.upper(),
                framework,
                f"[{score_color}]{snapshot.overall_score:.1f}[/]",
                snapshot.risk_level,
                str(snapshot.passing_checks),
                str(snapshot.failing_checks)
            )
        
        self.console.print(table)
        
        # Show recent drift events
        drift_events = [f for f in self.monitor._findings.values() if f.drift_detected]
        if drift_events:
            self.console.print("\n[bold yellow]Recent Drift Events:[/bold yellow]")
            
            drift_table = Table(box=box.ROUNDED)
            drift_table.add_column("Time", style="dim")
            drift_table.add_column("Check", style="cyan")
            drift_table.add_column("Change", justify="center")
            drift_table.add_column("Severity", style="yellow")
            
            for finding in sorted(drift_events, 
                                  key=lambda x: x.drift_timestamp or datetime.min,
                                  reverse=True)[:10]:
                time_str = finding.drift_timestamp.strftime("%H:%M:%S") if finding.drift_timestamp else "N/A"
                change = f"{finding.previous_state} → {finding.status}" if finding.previous_state else finding.status
                
                drift_table.add_row(
                    time_str,
                    finding.check_id[:50] + "..." if len(finding.check_id) > 50 else finding.check_id,
                    change,
                    finding.severity
                )
            
            self.console.print(drift_table)
    
    def get_compliance_score_over_time(self, provider: str = "aws") -> List[Dict]:
        """Get compliance score trend over time."""
        snapshots = [s for s in self.monitor._snapshots if s.provider == provider]
        return [
            {
                "timestamp": s.timestamp.isoformat(),
                "score": s.overall_score,
                "risk_level": s.risk_level,
                "passing": s.passing_checks,
                "total": s.total_checks,
            }
            for s in snapshots
        ]


async def main():
    """Example usage of real-time monitoring."""
    from odineyes.core.engine import ScanEngine
    
    # Initialize components
    scan_engine = ScanEngine()
    risk_engine = RiskEngine(framework="CVSS")
    monitor = RealTimeMonitor(scan_engine, risk_engine)
    
    console = Console()
    
    # Display help
    console.print(Panel.fit(
        """
[bold blue]Real-Time Compliance Monitoring Module[/bold blue]

This module provides:
• Continuous multi-cloud monitoring (AWS | Azure | GCP)
• Real-time drift detection between scan cycles
• Compliance score tracking over time
• Alerting on critical security events
• Multi-cloud compliance comparison

Usage examples:
1. Single scan: await monitor.run_once("aws")
2. Continuous monitoring: await monitor.run_continuous_monitoring(["aws", "azure"])
3. Get current findings: monitor.get_current_findings("aws")
6. Display dashboard: ComplianceDashboard(monitor).display_dashboard()
        """,
        title="Usage Guide",
        border_style="blue"
    ))


if __name__ == "__main__":
    asyncio.run(main())
