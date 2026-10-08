"""
Odineyes - Alert Suppression Engine
Filters out accepted risks based on a .odineyesignore file.
"""

import os
from typing import List, Dict, Any, Set
from rich.console import Console

from odineyes.utils.logger import setup_logger

logger = setup_logger()


class SuppressionEngine:
    """
    Suppresses findings based on user-defined rules.
    """

    def __init__(self, ignore_file: str = ".odineyesignore"):
        self.ignore_file = ignore_file
        self.console = Console()
        self.suppression_rules = self._load_rules()

    def _load_rules(self) -> Set[str]:
        """Loads suppression rules from the ignore file."""
        rules = set()
        if os.path.exists(self.ignore_file):
            try:
                with open(self.ignore_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            rules.add(line)
                self.console.print(f"[dim]Loaded {len(rules)} suppression rules from {self.ignore_file}[/dim]")
            except Exception as e:
                logger.error(f"Failed to load suppression rules: {e}")
        return rules

    def filter(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Applies suppression rules to the list of findings."""
        if not self.suppression_rules:
            return findings

        suppressed_count = 0
        for finding in findings:
            if finding.get("status") in ["pass", "skip"]:
                continue
            
            check_id = finding.get("check_id")
            resource_id = finding.get("resource_id")
            
            # Rule format: check_id:resource_id OR check_id:* OR *:resource_id
            rule_specific = f"{check_id}:{resource_id}"
            rule_check_all = f"{check_id}:*"
            rule_resource_all = f"*:{resource_id}"
            
            if rule_specific in self.suppression_rules or \
               rule_check_all in self.suppression_rules or \
               rule_resource_all in self.suppression_rules:
                
                finding["status"] = "skip"
                finding["message"] = f"[SUPPRESSED] {finding.get('message', '')}"
                finding["metadata"]["suppressed"] = True
                suppressed_count += 1
                
        if suppressed_count > 0:
            self.console.print(f"[yellow]Suppressed {suppressed_count} findings based on rules.[/yellow]")
            
        return findings
