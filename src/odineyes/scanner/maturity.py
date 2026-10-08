"""exploit_maturity — how weaponized a vulnerability actually is (0–1).

The Wiz risk factor that flips "CVSS 9.8 nobody exploits" below "CVSS 7.5 under
mass exploitation". KEV (known-exploited) is ground truth → 1.0; otherwise the
EPSS probability stands in.
"""
from __future__ import annotations

from typing import Optional


def exploit_maturity(epss: Optional[float], kev: bool) -> float:
    """0–1. KEV → 1.0 (confirmed in-the-wild); else the EPSS probability."""
    if kev:
        return 1.0
    return float(epss or 0.0)
