import unittest

from odineyes.core.compliance_mapper import ComplianceMapper, FRAMEWORKS


class TestComplianceScore(unittest.TestCase):
    """ComplianceMapper.score() — pure, no AWS calls."""

    def setUp(self):
        self.mapper = ComplianceMapper()

    def _find(self, check_id, status):
        return {"check_id": check_id, "status": status}

    def test_unknown_framework_skipped(self):
        out = self.mapper.score([], ["NOPE"])
        self.assertEqual(out, {})

    def test_no_findings_all_not_assessed(self):
        out = self.mapper.score([], ["CIS"])
        cis = out["CIS"]
        self.assertEqual(cis["total"], 0)
        self.assertEqual(cis["score"], 0)
        self.assertEqual(cis["passing"], 0)
        # Nothing ran, so every control in the scored universe (curated controls
        # plus any control a check maps to) is unassessed.
        self.assertEqual(cis["not_assessed"], len(cis["controls"]))
        self.assertGreaterEqual(cis["not_assessed"], len(FRAMEWORKS["CIS"]["controls"]))

    def test_pass_control_counts_toward_score(self):
        # iam_aws_001 maps to CIS 1.5. A passing finding → control passes.
        out = self.mapper.score([self._find("iam_aws_001", "pass")], ["CIS"])
        ctrl = next(c for c in out["CIS"]["controls"] if c["id"] == "1.5")
        self.assertEqual(ctrl["state"], "pass")
        self.assertEqual(out["CIS"]["passing"], 1)
        self.assertEqual(out["CIS"]["total"], 1)
        self.assertEqual(out["CIS"]["score"], 100)

    def test_fail_finding_fails_control(self):
        out = self.mapper.score([self._find("iam_aws_001", "fail")], ["CIS"])
        ctrl = next(c for c in out["CIS"]["controls"] if c["id"] == "1.5")
        self.assertEqual(ctrl["state"], "fail")
        self.assertEqual(out["CIS"]["passing"], 0)
        self.assertEqual(out["CIS"]["total"], 1)
        self.assertEqual(out["CIS"]["score"], 0)

    def test_error_finding_fails_control(self):
        out = self.mapper.score([self._find("iam_aws_001", "error")], ["CIS"])
        ctrl = next(c for c in out["CIS"]["controls"] if c["id"] == "1.5")
        self.assertEqual(ctrl["state"], "fail")

    def test_password_policy_check_maps_to_its_controls(self):
        # iam_aws_002 (password policy) evidences exactly CIS 1.8 (length) and
        # 1.9 (reuse) — not 1.10 (MFA, a different check) nor 1.11 (manual).
        out = self.mapper.score([self._find("iam_aws_002", "fail")], ["CIS"])
        scored = {c["id"]: c["state"] for c in out["CIS"]["controls"]
                  if c["state"] != "not_assessed"}
        self.assertEqual(set(scored), {"1.8", "1.9"})
        self.assertTrue(all(s == "fail" for s in scored.values()))
        self.assertEqual(out["CIS"]["total"], 2)
        self.assertEqual(out["CIS"]["passing"], 0)
        # 1.11 is a real (manual) control in the full catalog, never auto-assessed.
        self.assertIn("1.11", FRAMEWORKS["CIS"]["controls"])
        c111 = next(c for c in out["CIS"]["controls"] if c["id"] == "1.11")
        self.assertEqual(c111["state"], "not_assessed")

    def test_any_fail_among_resources_fails_control(self):
        # Same check, multiple resources: one fail makes the control fail.
        findings = [
            self._find("iam_aws_001", "pass"),
            self._find("iam_aws_001", "fail"),
        ]
        out = self.mapper.score(findings, ["CIS"])
        ctrl = next(c for c in out["CIS"]["controls"] if c["id"] == "1.5")
        self.assertEqual(ctrl["state"], "fail")

    def test_score_is_assessed_only(self):
        # One pass + one fail across two distinct controls → 50%.
        findings = [
            self._find("iam_aws_001", "pass"),   # CIS 1.5
            self._find("network_aws_001", "fail"),  # CIS 5.2
        ]
        out = self.mapper.score(findings, ["CIS"])
        self.assertEqual(out["CIS"]["total"], 2)
        self.assertEqual(out["CIS"]["passing"], 1)
        self.assertEqual(out["CIS"]["score"], 50)
        # Unassessed controls excluded from denominator.
        self.assertGreater(out["CIS"]["not_assessed"], 0)

    def test_sections_aggregate(self):
        out = self.mapper.score([self._find("iam_aws_001", "pass")], ["CIS"])
        iam_sec = out["CIS"]["sections"]["Identity and Access Management"]
        self.assertEqual(iam_sec["passing"], 1)
        self.assertEqual(iam_sec["total"], 1)
        self.assertEqual(iam_sec["pct"], 100)

    def test_multiple_frameworks(self):
        out = self.mapper.score([self._find("iam_aws_001", "fail")], ["CIS", "PCI-DSS"])
        self.assertIn("CIS", out)
        self.assertIn("PCI-DSS", out)
        # iam_aws_001 maps to PCI-DSS 8.3.1.
        pci = next(c for c in out["PCI-DSS"]["controls"] if c["id"] == "8.3.1")
        self.assertEqual(pci["state"], "fail")


if __name__ == "__main__":
    unittest.main()
