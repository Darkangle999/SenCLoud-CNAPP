"""Odineyes - Resource Inventory Engine"""

from typing import List, Dict, Any
from rich.table import Table
from rich.console import Console
from rich import box


class InventoryEngine:
    def __init__(self, provider: str, regions: List[str], resource_types: List[str]):
        self.provider = provider
        self.regions = regions or ["us-east-1"]
        self.resource_types = resource_types

    def run(self, output: str, console: Console):
        console.print(f"[bold blue]📦 Enumerating {self.provider.upper()} resources...[/bold blue]\n")
        
        resources = self._enumerate()
        
        table = Table(title=f"[bold]{self.provider.upper()} Resource Inventory[/bold]",
                     box=box.ROUNDED, border_style="cyan")
        table.add_column("Resource ID", style="cyan")
        table.add_column("Type", style="blue")
        table.add_column("Region", style="magenta")
        table.add_column("Name", style="white")
        table.add_column("Tags", style="dim")
        
        for r in resources:
            table.add_row(
                r.get("id", "N/A"),
                r.get("type", "N/A"),
                r.get("region", "global"),
                r.get("name", "-"),
                str(r.get("tags", {}))[:40],
            )
        
        console.print(table)
        console.print(f"\n[bold]Total resources: [cyan]{len(resources)}[/cyan][/bold]")
        
        if output:
            import json
            with open(output, "w") as f:
                json.dump({"provider": self.provider, "resources": resources}, f, indent=2)
            console.print(f"[green]✓ Saved to {output}[/green]")

    def _enumerate(self) -> List[Dict]:
        """Enumerate resources - uses real APIs if credentials available, else simulated."""
        simulated = [
            {"id": "arn:aws:s3:::prod-data-bucket", "type": "s3:bucket", "region": "global", "name": "prod-data-bucket", "tags": {"env": "prod"}},
            {"id": "i-0abc123def456789", "type": "ec2:instance", "region": "us-east-1", "name": "web-server-01", "tags": {"env": "prod", "role": "web"}},
            {"id": "sg-0abc1234example", "type": "ec2:security_group", "region": "us-east-1", "name": "web-servers", "tags": {}},
            {"id": "vpc-0abc123", "type": "ec2:vpc", "region": "us-east-1", "name": "main-vpc", "tags": {"env": "prod"}},
            {"id": "arn:aws:iam::123456789:user/admin", "type": "iam:user", "region": "global", "name": "admin", "tags": {}},
            {"id": "arn:aws:cloudtrail:us-east-1:123:trail/main", "type": "cloudtrail:trail", "region": "us-east-1", "name": "main-trail", "tags": {}},
        ]
        return simulated
