"""
Odineyes - Risk Scoring Engine
Implements CVSS, DREAD, and FAIR risk scoring models.
"""

from typing import List, Dict, Any, Optional
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich import box


class RiskEngine:
    """
    Multi-framework risk scoring engine.
    Supports CVSS (default), DREAD, and FAIR methodologies.
    """
    
    SEVERITY_SCORES = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "informational": 0.5,
    }
    
    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
        "informational": 0,
    }
    
    def __init__(self, framework: str = "CVSS"):
        self.framework = framework
    
    def calculate_finding_score(self, finding: Dict[str, Any]) -> float:
        """Calculate risk score for a single finding."""
        if finding.get("status") in ["pass", "skip"]:
            return 0.0
        
        severity = finding.get("severity", "low").lower()
        base_score = self.SEVERITY_SCORES.get(severity, 2.5)
        risk_weight = finding.get("risk_weight", 1.0)
        
        # Adjust based on framework
        if self.framework == "CVSS":
            return self._cvss_score(base_score, finding)
        elif self.framework == "DREAD":
            return self._dread_score(finding)
        else:  # FAIR
            return self._fair_score(base_score, finding)
    
    def _cvss_score(self, base_score: float, finding: Dict) -> float:
        """CVSS-inspired scoring."""
        # Simplified CVSS v3.1 environmental scoring
        category = finding.get("category", "")
        
        # Confidentiality/Integrity/Availability impact multipliers
        category_multipliers = {
            "iam": 1.2,       # High impact on all three pillars
            "network": 1.1,
            "storage": 1.15,
            "encryption": 1.1,
            "logging": 0.9,
            "compute": 1.05,
        }
        multiplier = category_multipliers.get(category, 1.0)
        score = min(base_score * multiplier, 10.0)
        return round(score, 1)
    
    def _dread_score(self, finding: Dict) -> float:
        """DREAD model: Damage, Reproducibility, Exploitability, Affected users, Discoverability."""
        severity = finding.get("severity", "low").lower()
        d_scores = {"critical": 9, "high": 7, "medium": 5, "low": 3, "informational": 1}
        base = d_scores.get(severity, 3)
        # D + R + E + A + D / 5
        dread = (base + 8 + base + base + 6) / 5
        return round(min(dread, 10.0), 1)
    
    def _fair_score(self, base_score: float, finding: Dict) -> float:
        """FAIR model: Factor Analysis of Information Risk."""
        # Simplified: Loss Event Frequency × Loss Magnitude
        severity = finding.get("severity", "low").lower()
        lef = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3, "informational": 0.1}
        lm = {"critical": 10, "high": 8, "medium": 6, "low": 4, "informational": 2}
        score = lef.get(severity, 0.3) * lm.get(severity, 4)
        return round(min(score, 10.0), 1)
    
    def calculate_overall_score(self, findings: List[Dict]) -> float:
        """
        Calculate aggregate risk score (0-100) for all findings.
        Weighted sum of findings normalized to 0-100.
        """
        if not findings:
            return 0.0
        
        failed = [f for f in findings if f.get("status") not in ["pass", "skip"]]
        if not failed:
            return 0.0
        
        total_weight = sum(self.SEVERITY_WEIGHTS.values()) * len(findings)
        actual_weight = sum(
            self.SEVERITY_WEIGHTS.get(f.get("severity", "low").lower(), 1)
            for f in failed
        )
        
        # Normalize to 0-100
        raw_score = (actual_weight / max(total_weight, 1)) * 100
        return round(min(raw_score * 3, 100), 1)  # Scale up for realism
    
    def score_to_level(self, score: float) -> str:
        """Convert numeric score to risk level label."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def display_scores(self, results: Dict, console: Console):
        """Display risk scores in a rich formatted table."""
        findings = results.get("findings", [])
        risk_score = results.get("risk_score", self.calculate_overall_score(findings))
        risk_level = results.get("risk_level", self.score_to_level(risk_score))
        
        level_colors = {
            "CRITICAL": "red", "HIGH": "orange3",
            "MEDIUM": "yellow", "LOW": "green", "MINIMAL": "bright_green"
        }
        color = level_colors.get(risk_level, "white")
        
        # Overall score panel
        score_bar = "█" * int(risk_score / 5) + "░" * (20 - int(risk_score / 5))
        console.print(Panel(
            f"[bold {color}]Overall Risk Score: {risk_score}/100 — {risk_level}[/bold {color}]\n"
            f"[{color}]{score_bar}[/{color}]\n"
            f"Framework: [cyan]{self.framework}[/cyan]",
            title="[bold]Risk Assessment[/bold]",
            border_style=color,
        ))
        
        # Per-category breakdown
        category_scores: Dict[str, List[float]] = {}
        for f in findings:
            if f.get("status") != "pass":
                cat = f.get("category", "unknown")
                score = f.get("risk_score") or self.calculate_finding_score(f)
                category_scores.setdefault(cat, []).append(score)
        
        if category_scores:
            table = Table(title="Risk by Category", box=box.ROUNDED, border_style="blue")
            table.add_column("Category", style="cyan")
            table.add_column("Findings", justify="right")
            table.add_column("Avg Score", justify="right")
            table.add_column("Max Score", justify="right")
            table.add_column("Risk Level")
            
            for cat, scores in sorted(category_scores.items()):
                avg = sum(scores) / len(scores)
                mx = max(scores)
                level = self.score_to_level(avg * 10)
                level_color = level_colors.get(level, "white")
                table.add_row(
                    cat, str(len(scores)),
                    f"{avg:.1f}", f"{mx:.1f}",
                    f"[{level_color}]{level}[/{level_color}]"
                )
            
            console.print(table)
