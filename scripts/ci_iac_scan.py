#!/usr/bin/env python3
"""CI gate: run Checkov or Trivy over a repo's IaC and exit non-zero on
HIGH/CRITICAL so the pipeline blocks the merge/deploy (gap analysis §4.8).

Engine-agnostic hook for GitLab CI / Jenkins / local pre-push. GitHub Actions
users get the same gate from `.github/workflows/iac-scan.yml`.

Usage:
    pip install checkov      # when using --engine checkov
    # for trivy, install the binary first (scripts/install-trivy.sh)
    python scripts/ci_iac_scan.py [PATH]        # PATH defaults to "."

Env:
    IAC_ENGINE   engine to run: "checkov" (default) or "trivy"
    IAC_FAIL_ON   comma-separated severities that fail the build
                  (default: "high,critical")

Exit codes: 0 = no blocking findings · 1 = blocking findings · 2 = engine missing.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from odineyes.iac import checkov_runner, trivy_runner  # noqa: E402


def _runner(engine: str):
    return {"checkov": checkov_runner, "trivy": trivy_runner}[engine]


def main(path: str) -> int:
    engine = (os.environ.get("IAC_ENGINE") or "checkov").lower()
    runner = _runner(engine)
    if not runner.available():
        print(f"{engine} not installed — run scripts/install-trivy.sh (trivy) or: pip install checkov",
              file=sys.stderr)
        return 2

    res = runner.scan_dir(path)
    fail_on = {s.strip().lower() for s in (os.environ.get("IAC_FAIL_ON") or "high,critical").split(",") if s.strip()}
    blocking = [f for f in res["findings"] if f["severity"] in fail_on]

    print(f"{engine}: {res['total']} findings {res['by_severity']}; "
          f"{len(blocking)} blocking (fail on: {','.join(sorted(fail_on))})")
    for f in blocking[:100]:
        print(f"  [{f['severity'].upper()}] {f['check_id']} {f['resource']} — {f['title']}")

    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
