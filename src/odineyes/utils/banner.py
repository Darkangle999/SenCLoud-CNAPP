"""Odineyes - ASCII Banner"""

from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from rich.console import Console


BANNER = r"""
   ________ __              __  _____            __  _          __
  / ____/ // /__  __ _____/ / / ___/___  ____  / /_(_)__  ___ / /
 / /   / // // / / // __  /  \__ \/ -_)/ _  \/ __/ // _ \/ -_) / 
/ /___/ // // /_/ // /_/ /  ___/ / _  / / / / /_/ // // / _  / /  
\____/_//_/ \__,_/ \__,_/  /____/\___/_/ /_/\__/_//_/\_, /\___/_/   v2.0
                                                     /___/          
"""


def print_banner(console: Console):
    banner_text = Text()
    banner_text.append("   ██████╗██╗      ██████╗ ██╗   ██╗██████╗      ", style="bold blue")
    banner_text.append("\n", style="")
    banner_text.append("  ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗     ", style="bold blue")
    banner_text.append("\n", style="")
    banner_text.append("  ██║     ██║     ██║   ██║██║   ██║██║  ██║     ", style="bold cyan")
    banner_text.append("\n", style="")
    banner_text.append("  ██║     ██║     ██║   ██║██║   ██║██║  ██║     ", style="bold cyan")
    banner_text.append("\n", style="")
    banner_text.append("  ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝     ", style="bold blue")
    banner_text.append("\n", style="")
    banner_text.append("   ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝      ", style="bold blue")
    
    subtitle = Text()
    subtitle.append("\n  🛡 Odineyes v2.0  ", style="bold white")
    subtitle.append("Multicloud GRC Security Platform\n", style="dim")
    subtitle.append("  AWS • Azure • GCP  |  CIS • SOC2 • HIPAA • PCI-DSS • NIST • ISO27001\n", style="dim cyan")
    
    console.print(Panel(
        Align.center(Text.assemble(banner_text, subtitle)),
        border_style="blue",
        padding=(0, 2),
    ))
    console.print()
