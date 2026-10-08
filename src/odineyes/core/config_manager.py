"""Odineyes - Configuration Manager"""

import os
import json
from typing import List, Dict, Optional
from rich.table import Table
from rich.console import Console
from rich import box

CONFIG_PATH = os.path.expanduser("~/.odineyes/config.json")
DEFAULT_CONFIG = {
    "aws": {"profile": "default", "regions": ["us-east-1"], "scanner_instance_id": None},
    "azure": {"subscription_id": None},
    "gcp": {"project_id": None},
    "defaults": {"threads": 10, "output_format": "html"},
}


class ConfigManager:
    def __init__(self, config_file: str = None):
        self._path = config_file or CONFIG_PATH
        self._config = self._load()

    def _load(self) -> Dict:
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    return json.load(f)
            except Exception:
                pass
        return DEFAULT_CONFIG.copy()

    def _save(self):
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._config, f, indent=2)

    def get_all_providers(self) -> List[str]:
        """Return all supported providers (for --all-providers flag)."""
        return ["aws", "azure", "gcp"]

    def get_configured_providers(self) -> List[str]:
        """Return only providers that have credentials/config set."""
        providers = []
        if self._config.get("aws", {}).get("profile"):
            providers.append("aws")
        if self._config.get("azure", {}).get("subscription_id"):
            providers.append("azure")
        if self._config.get("gcp", {}).get("project_id"):
            providers.append("gcp")
        return providers or ["aws"]

    def get_default_regions(self, provider: str) -> List[str]:
        return self._config.get(provider, {}).get("regions", ["us-east-1"])

    def set_provider(self, provider: str, **kwargs):
        self._config.setdefault(provider, {}).update({k: v for k, v in kwargs.items() if v})
        self._save()

    def display(self, provider: str, console: Console):
        table = Table(title=f"Odineyes Configuration — {provider.upper()}", 
                     box=box.ROUNDED, border_style="blue")
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        for k, v in self._config.get(provider, {}).items():
            table.add_row(k, str(v) if v else "[dim]not set[/dim]")
        console.print(table)
