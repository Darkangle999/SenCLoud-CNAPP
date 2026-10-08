"""Offline CVSS v3.x base-score calculator + severity banding.

Lets us derive a severity from the CVSS vector OSV already returns, without a
network round-trip — so a vuln is never left "unknown" when a vector exists.
Implements the CVSS v3.1 base-score spec (FIRST.org).
"""

from __future__ import annotations

import math
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    # CVSS spec round-up to 1 decimal, with the int-arithmetic fudge.
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> Optional[float]:
    """CVSS v3.x base score from a vector string, or None if unparseable."""
    if not vector:
        return None
    parts = dict(
        kv.split(":", 1) for kv in vector.split("/") if ":" in kv and not kv.startswith("CVSS")
    )
    try:
        av, ac, ui = _AV[parts["AV"]], _AC[parts["AC"]], _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def band(score: Optional[float]) -> str:
    """CVSS qualitative severity rating."""
    if score is None:
        return "unknown"
    if score == 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
