"""
Odineyes — Test Suite
Run with: pytest tests/ -v
"""
import sys
import os
import json
import types
import unittest
from unittest.mock import MagicMock, patch

# ─── Stub external dependencies so tests run without cloud SDKs ───

def _make_rich_stubs():
    mods = {}
    for name in ['rich', 'rich.console', 'rich.table', 'rich.box', 'rich.panel',
                 'rich.text', 'rich.progress', 'rich.live', 'rich.align', 'rich.layout']:
        mods[name] = types.ModuleType(name)

    class FakeConsole:
        def print(self, *a, **kw): pass

    class FakeTable:
        def __init__(self, *a, **kw): pass
        def add_column(self, *a, **kw): pass
        def add_row(self, *a, **kw): pass

    class FakeProgress:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def add_task(self, *a, **kw): return 0
        def advance(self, *a): pass
        def update(self, *a, **kw): pass

    mods['rich.console'].Console = FakeConsole
    mods['rich.table'].Table = FakeTable
    for attr in ['ROUNDED', 'SIMPLE', 'MINIMAL']:
        setattr(mods['rich.box'], attr, None)
    mods['rich.panel'].Panel = type('Panel', (), {'__init__': lambda s, *a, **kw: None})
    mods['rich.text'].Text = type('Text', (), {
        '__init__': lambda s, *a, **kw: None,
        'append': lambda s, *a, **kw: None,
        'assemble': staticmethod(lambda *a: None),
    })
    mods['rich.progress'].Progress = FakeProgress
    for cls in ['SpinnerColumn', 'BarColumn', 'TaskProgressColumn', 'TimeElapsedColumn']:
        setattr(mods['rich.progress'], cls, type(cls, (), {'__init__': lambda s, *a, **kw: None}))
    mods['rich.progress'].TextColumn = lambda *a, **kw: None
    mods['rich.live'].Live = type('Live', (), {'__enter__': lambda s: s, '__exit__': lambda s, *a: None})
    mods['rich.align'].Align = type('Align', (), {'center': staticmethod(lambda x: x)})
    return mods


_stubs = _make_rich_stubs()
for k, v in _stubs.items():
    sys.modules[k] = v

# Stub utils
_utils = types.ModuleType('utils')
_logger = types.ModuleType('utils.logger')
_logger.setup_logger = lambda *a, **kw: __import__('logging').getLogger('test')
_banner = types.ModuleType('utils.banner')
_banner.print_banner = lambda *a: None
sys.modules['utils'] = _utils
sys.modules['utils.logger'] = _logger
sys.modules['utils.banner'] = _banner

# Now import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from odineyes.core.check_registry import (
    CheckRegistry, BaseCheck,
    AWSRootAccountMFACheck, AWSIAMPasswordPolicyCheck,
    AWSIAMAccessKeyRotationCheck, AWSIAMNoRootAccessKeys,
    AWSS3PublicAccessBlockCheck, AWSS3EncryptionCheck,
    AWSSecurityGroupOpenSSHCheck, AWSVPCFlowLogsCheck,
    AWSCloudTrailMultiRegionCheck,
    AzureMFAEnabledCheck, AzureStorageAccountHTTPSCheck,
    GCPServiceAccountKeyRotation, GCPStorageBucketPublicCheck,
)
from odineyes.core.risk_engine import RiskEngine
from odineyes.core.compliance_mapper import ComplianceMapper, FRAMEWORKS
from odineyes.core.report_builder import ReportBuilder


# ─────────────────────────────────────────────────────────────
# CheckRegistry Tests
# ─────────────────────────────────────────────────────────────

class TestCheckRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = CheckRegistry()
        self.ctx = {'provider': 'aws', 'regions': ['us-east-1'], 'profile': 'default'}

    def test_registry_loads_all_checks(self):
        checks = self.registry.resolve_checks(['aws', 'azure', 'gcp'], ['all'], [], [])
        self.assertGreater(len(checks), 10, "Should have more than 10 built-in checks")

    def test_filter_by_provider_aws(self):
        checks = self.registry.resolve_checks(['aws'], ['all'], [], [])
        self.assertTrue(all(c.provider == 'aws' for c in checks))
        self.assertGreater(len(checks), 0)

    def test_filter_by_provider_azure(self):
        checks = self.registry.resolve_checks(['azure'], ['all'], [], [])
        self.assertTrue(all(c.provider == 'azure' for c in checks))

    def test_filter_by_provider_gcp(self):
        checks = self.registry.resolve_checks(['gcp'], ['all'], [], [])
        self.assertTrue(all(c.provider == 'gcp' for c in checks))

    def test_filter_by_category_iam(self):
        checks = self.registry.resolve_checks(['aws'], ['iam'], [], [])
        self.assertTrue(all(c.category == 'iam' for c in checks))

    def test_filter_by_specific_check_id(self):
        checks = self.registry.resolve_checks(['aws'], ['all'], ['iam_aws_001'], [])
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].check_id, 'iam_aws_001')

    def test_exclude_check(self):
        all_checks = self.registry.resolve_checks(['aws'], ['all'], [], [])
        excluded = self.registry.resolve_checks(['aws'], ['all'], [], ['iam_aws_001'])
        ids = [c.check_id for c in excluded]
        self.assertNotIn('iam_aws_001', ids)
        self.assertEqual(len(excluded), len(all_checks) - 1)

    def test_checks_have_required_metadata(self):
        checks = self.registry.resolve_checks(['aws', 'azure', 'gcp'], ['all'], [], [])
        required = ['check_id', 'name', 'description', 'provider', 'category', 'severity']
        for check in checks:
            for attr in required:
                self.assertTrue(hasattr(check, attr), f"{check.check_id} missing {attr}")
                self.assertTrue(getattr(check, attr), f"{check.check_id}.{attr} is empty")

    def test_severity_values_valid(self):
        valid = {'critical', 'high', 'medium', 'low', 'informational'}
        checks = self.registry.resolve_checks(['aws', 'azure', 'gcp'], ['all'], [], [])
        for check in checks:
            self.assertIn(check.severity, valid, f"{check.check_id} has invalid severity {check.severity}")

    def test_provider_values_valid(self):
        valid = {'aws', 'azure', 'gcp'}
        checks = self.registry.resolve_checks(['aws', 'azure', 'gcp'], ['all'], [], [])
        for check in checks:
            self.assertIn(check.provider, valid)


# ─────────────────────────────────────────────────────────────
# Individual Check Tests
# ─────────────────────────────────────────────────────────────

class TestAWSChecks(unittest.TestCase):

    def setUp(self):
        self.ctx = {'provider': 'aws', 'regions': ['us-east-1'], 'profile': 'default'}

    def _assert_valid_finding(self, finding):
        """Assert a finding has all required fields."""
        required = ['check_id', 'name', 'provider', 'category', 'severity',
                    'status', 'resource_id', 'resource_type', 'region', 'message']
        for field in required:
            self.assertIn(field, finding, f"Finding missing field: {field}")
        self.assertIn(finding['status'], ['pass', 'fail', 'error', 'skip'])

    def test_root_mfa_check_returns_findings(self):
        check = AWSRootAccountMFACheck()
        findings = check.execute(self.ctx)
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self._assert_valid_finding(f)
            self.assertEqual(f['check_id'], 'iam_aws_001')
            self.assertEqual(f['severity'], 'critical')

    def test_password_policy_check_returns_findings(self):
        check = AWSIAMPasswordPolicyCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self._assert_valid_finding(f)
            self.assertEqual(f['check_id'], 'iam_aws_002')

    def test_access_key_rotation_check(self):
        check = AWSIAMAccessKeyRotationCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self._assert_valid_finding(f)

    def test_no_root_access_keys_check(self):
        check = AWSIAMNoRootAccessKeys()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self._assert_valid_finding(f)
            self.assertEqual(f['severity'], 'critical')

    def test_s3_public_access_check(self):
        check = AWSS3PublicAccessBlockCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self._assert_valid_finding(f)
            self.assertEqual(f['category'], 'storage')

    def test_s3_encryption_check(self):
        check = AWSS3EncryptionCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)

    def test_sg_open_ssh_check(self):
        check = AWSSecurityGroupOpenSSHCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self._assert_valid_finding(f)
            self.assertEqual(f['severity'], 'critical')

    def test_vpc_flow_logs_check(self):
        check = AWSVPCFlowLogsCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)

    def test_cloudtrail_multiregion_check(self):
        check = AWSCloudTrailMultiRegionCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)

    def test_check_compliance_mappings_present(self):
        """All checks should have at least one compliance framework mapped."""
        checks = [
            AWSRootAccountMFACheck(), AWSIAMPasswordPolicyCheck(),
            AWSS3PublicAccessBlockCheck(), AWSCloudTrailMultiRegionCheck(),
        ]
        for check in checks:
            self.assertIsInstance(check.compliance, dict)
            self.assertGreater(len(check.compliance), 0, f"{check.check_id} has no compliance mappings")

    def test_check_has_remediation(self):
        """Checks should have remediation guidance."""
        checks = [AWSRootAccountMFACheck(), AWSS3PublicAccessBlockCheck()]
        for check in checks:
            self.assertTrue(check.remediation, f"{check.check_id} missing remediation")


class TestAzureChecks(unittest.TestCase):
    def setUp(self):
        self.ctx = {'provider': 'azure', 'subscription_id': 'test-sub-id'}

    def test_azure_mfa_check(self):
        check = AzureMFAEnabledCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertEqual(f['provider'], 'azure')

    def test_azure_storage_https_check(self):
        check = AzureStorageAccountHTTPSCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)


class TestGCPChecks(unittest.TestCase):
    def setUp(self):
        self.ctx = {'provider': 'gcp', 'project_id': 'test-project'}

    def test_gcp_service_account_key_rotation(self):
        check = GCPServiceAccountKeyRotation()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertEqual(f['provider'], 'gcp')

    def test_gcp_storage_public_check(self):
        check = GCPStorageBucketPublicCheck()
        findings = check.execute(self.ctx)
        self.assertGreater(len(findings), 0)


# ─────────────────────────────────────────────────────────────
# Risk Engine Tests
# ─────────────────────────────────────────────────────────────

class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RiskEngine()

    def _make_finding(self, severity, status='fail', category='iam'):
        return {
            'severity': severity,
            'status': status,
            'category': category,
            'provider': 'aws',
        }

    def test_cvss_critical_score_is_high(self):
        f = self._make_finding('critical')
        score = self.engine.calculate_finding_score(f)
        self.assertGreater(score, 9.0)

    def test_cvss_low_score_is_low(self):
        f = self._make_finding('low')
        score = self.engine.calculate_finding_score(f)
        self.assertLess(score, 4.0)

    def test_pass_findings_score_zero(self):
        f = self._make_finding('critical', status='pass')
        score = self.engine.calculate_finding_score(f)
        self.assertEqual(score, 0.0)

    def test_score_bounded_0_to_10(self):
        for sev in ['critical', 'high', 'medium', 'low', 'informational']:
            f = self._make_finding(sev)
            score = self.engine.calculate_finding_score(f)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 10.0)

    def test_dread_framework(self):
        engine = RiskEngine('DREAD')
        f = self._make_finding('high')
        score = engine.calculate_finding_score(f)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 10.0)

    def test_fair_framework(self):
        engine = RiskEngine('FAIR')
        f = self._make_finding('critical')
        score = engine.calculate_finding_score(f)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 10.0)

    def test_overall_score_no_findings(self):
        score = self.engine.calculate_overall_score([])
        self.assertEqual(score, 0.0)

    def test_overall_score_all_pass(self):
        findings = [self._make_finding('critical', status='pass') for _ in range(5)]
        score = self.engine.calculate_overall_score(findings)
        self.assertEqual(score, 0.0)

    def test_overall_score_with_failures(self):
        findings = [
            self._make_finding('critical'),
            self._make_finding('high'),
            self._make_finding('medium'),
            self._make_finding('low', status='pass'),
        ]
        score = self.engine.calculate_overall_score(findings)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 100.0)

    def test_score_to_level_mapping(self):
        self.assertEqual(self.engine.score_to_level(90), 'CRITICAL')
        self.assertEqual(self.engine.score_to_level(65), 'HIGH')
        self.assertEqual(self.engine.score_to_level(45), 'MEDIUM')
        self.assertEqual(self.engine.score_to_level(25), 'LOW')
        self.assertEqual(self.engine.score_to_level(5), 'MINIMAL')

    def test_severity_order(self):
        """Critical should always score higher than lower severities."""
        engine = self.engine
        scores = {
            sev: engine.calculate_finding_score({'severity': sev, 'status': 'fail', 'category': 'iam'})
            for sev in ['critical', 'high', 'medium', 'low']
        }
        self.assertGreater(scores['critical'], scores['high'])
        self.assertGreater(scores['high'], scores['medium'])
        self.assertGreater(scores['medium'], scores['low'])


# ─────────────────────────────────────────────────────────────
# Compliance Mapper Tests
# ─────────────────────────────────────────────────────────────

class TestComplianceMapper(unittest.TestCase):

    def setUp(self):
        self.mapper = ComplianceMapper()

    def test_all_frameworks_defined(self):
        for fw in ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS', 'NIST', 'ISO27001', 'GDPR', 'FedRAMP']:
            self.assertIn(fw, FRAMEWORKS, f"Framework {fw} not defined")

    def test_frameworks_have_controls(self):
        for fw_name, fw_data in FRAMEWORKS.items():
            self.assertIn('controls', fw_data, f"{fw_name} missing controls")
            self.assertGreater(len(fw_data['controls']), 0, f"{fw_name} has no controls")
            self.assertIn('name', fw_data, f"{fw_name} missing name")

    def test_map_finding_cis(self):
        finding = {
            'check_id': 'iam_aws_001',
            'severity': 'critical',
            'status': 'fail',
            'provider': 'aws',
        }
        mappings = self.mapper.map_finding(finding, ['CIS'])
        self.assertIn('CIS', mappings)
        self.assertIsInstance(mappings['CIS'], list)
        self.assertGreater(len(mappings['CIS']), 0)

    def test_map_finding_multiple_frameworks(self):
        finding = {'check_id': 'iam_aws_001', 'severity': 'critical', 'status': 'fail'}
        mappings = self.mapper.map_finding(finding, ['CIS', 'SOC2', 'NIST'])
        # At least one framework should have mappings for root MFA check
        total_mappings = sum(len(v) for v in mappings.values())
        self.assertGreater(total_mappings, 0)

    def test_map_finding_unknown_check(self):
        finding = {'check_id': 'nonexistent_999', 'severity': 'low', 'status': 'fail'}
        mappings = self.mapper.map_finding(finding, ['CIS'])
        # Should return empty dict, not raise
        self.assertIsInstance(mappings, dict)

    def test_cis_controls_have_titles(self):
        cis = FRAMEWORKS['CIS']['controls']
        for ctrl_id, ctrl_data in cis.items():
            self.assertIn('title', ctrl_data, f"CIS {ctrl_id} missing title")
            self.assertTrue(ctrl_data['title'], f"CIS {ctrl_id} has empty title")

    def test_nist_controls_have_titles(self):
        nist = FRAMEWORKS['NIST']['controls']
        for ctrl_id, ctrl_data in nist.items():
            self.assertIn('title', ctrl_data)


# ─────────────────────────────────────────────────────────────
# Report Builder Tests
# ─────────────────────────────────────────────────────────────

class TestReportBuilder(unittest.TestCase):

    def setUp(self):
        self.sample_results = {
            'scan_metadata': {
                'tool': 'Odineyes', 'version': '2.0.0',
                'scan_id': 'CS-TEST-001',
                'start_time': '2024-01-01T00:00:00+00:00',
                'end_time': '2024-01-01T00:00:05+00:00',
                'duration_seconds': 5.0,
                'providers': ['aws'],
                'regions': ['us-east-1'],
                'checks_run': 9,
                'compliance_frameworks': ['CIS'],
            },
            'summary': {
                'total_checks': 5,
                'passed': 2,
                'failed': 3,
                'errors': 0,
                'pass_rate': 40.0,
                'by_severity': {'critical': 2, 'high': 1},
                'by_provider': {'aws': 3},
                'by_category': {'iam': 2, 'storage': 1},
            },
            'risk_score': 72.5,
            'risk_level': 'HIGH',
            'findings': [
                {
                    'check_id': 'iam_aws_001',
                    'name': 'Root Account MFA',
                    'provider': 'aws',
                    'category': 'iam',
                    'severity': 'critical',
                    'status': 'fail',
                    'resource_id': 'root',
                    'resource_type': 'iam:root_account',
                    'region': 'global',
                    'message': 'Root account has no MFA',
                    'remediation': 'Enable MFA on root account',
                    'risk_score': 9.5,
                    'compliance_mappings': {'CIS': ['1.5']},
                    'metadata': {},
                    'timestamp': '2024-01-01T00:00:01+00:00',
                },
                {
                    'check_id': 'storage_aws_001',
                    'name': 'S3 Public Access',
                    'provider': 'aws',
                    'category': 'storage',
                    'severity': 'critical',
                    'status': 'fail',
                    'resource_id': 'arn:aws:s3:::prod-bucket',
                    'resource_type': 's3:bucket',
                    'region': 'global',
                    'message': 'Bucket is publicly accessible',
                    'remediation': 'Enable public access block',
                    'risk_score': 9.5,
                    'compliance_mappings': {'CIS': ['2.1.5']},
                    'metadata': {},
                    'timestamp': '2024-01-01T00:00:02+00:00',
                },
                {
                    'check_id': 'iam_aws_002',
                    'name': 'Password Policy',
                    'provider': 'aws',
                    'category': 'iam',
                    'severity': 'high',
                    'status': 'pass',
                    'resource_id': 'account_password_policy',
                    'resource_type': 'iam:password_policy',
                    'region': 'global',
                    'message': 'Password policy OK',
                    'remediation': '',
                    'risk_score': 0,
                    'compliance_mappings': {},
                    'metadata': {},
                    'timestamp': '2024-01-01T00:00:03+00:00',
                },
            ],
        }

    def test_generate_json(self, tmp_path=None):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, 'report')
            builder = ReportBuilder(self.sample_results, ['CIS'])
            path = builder.generate('json', out)
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)
            self.assertIn('findings', data)
            self.assertEqual(len(data['findings']), 3)

    def test_generate_csv(self):
        import tempfile, os, csv
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, 'report')
            builder = ReportBuilder(self.sample_results, ['CIS'])
            path = builder.generate('csv', out)
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 3)
            self.assertIn('check_id', rows[0])
            self.assertIn('severity', rows[0])
            self.assertIn('status', rows[0])

    def test_generate_html(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, 'report')
            builder = ReportBuilder(self.sample_results, ['CIS'])
            path = builder.generate('html', out)
            self.assertTrue(os.path.exists(path))
            content = open(path, encoding="utf-8").read()
            self.assertIn('Odineyes', content)
            self.assertIn('iam_aws_001', content)
            self.assertIn('chart.js', content)
            self.assertIn('CRITICAL', content)
            self.assertGreater(len(content), 10000)

    def test_html_contains_findings(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, 'report')
            builder = ReportBuilder(self.sample_results, ['CIS'])
            path = builder.generate('html', out)
            content = open(path, encoding="utf-8").read()
            # Should contain the failed findings
            self.assertIn('Root account has no MFA', content)
            self.assertIn('publicly accessible', content)

    def test_invalid_format_raises(self):
        builder = ReportBuilder(self.sample_results)
        with self.assertRaises(ValueError):
            builder.generate('pdf', '/tmp/test')


# ─────────────────────────────────────────────────────────────
# Integration Test — Full Pipeline
# ─────────────────────────────────────────────────────────────

class TestFullPipeline(unittest.TestCase):

    def test_full_scan_pipeline(self):
        """Test complete: registry → checks → risk scoring → compliance → report."""
        registry = CheckRegistry()
        risk_engine = RiskEngine()
        mapper = ComplianceMapper()

        # Resolve checks
        checks = registry.resolve_checks(['aws'], ['all'], [], [])
        self.assertGreater(len(checks), 0)

        # Execute all AWS checks
        all_findings = []
        ctx = {'provider': 'aws', 'regions': ['us-east-1'], 'profile': 'default'}
        for check in checks:
            findings = check.execute(ctx)
            self.assertIsInstance(findings, list)
            for f in findings:
                f['risk_score'] = risk_engine.calculate_finding_score(f)
                f['compliance_mappings'] = mapper.map_finding(f, ['CIS', 'SOC2'])
                all_findings.append(f)

        self.assertGreater(len(all_findings), 0)

        # Risk scoring
        overall_score = risk_engine.calculate_overall_score(all_findings)
        self.assertGreaterEqual(overall_score, 0)
        self.assertLessEqual(overall_score, 100)

        # Verify compliance mappings populated
        check_with_mappings = [
            f for f in all_findings
            if f.get('compliance_mappings') and any(v for v in f['compliance_mappings'].values())
        ]
        self.assertGreater(len(check_with_mappings), 0, "Some findings should have compliance mappings")

        # Generate reports
        import tempfile, os
        passed = sum(1 for f in all_findings if f.get('status') == 'pass')
        failed = len(all_findings) - passed
        sev_counts = {}
        for f in all_findings:
            if f.get('status') != 'pass':
                s = f.get('severity', 'low')
                sev_counts[s] = sev_counts.get(s, 0) + 1

        results = {
            'scan_metadata': {
                'tool': 'Odineyes', 'version': '2.0.0',
                'scan_id': 'CS-INT-001',
                'start_time': '2024-01-01T00:00:00+00:00',
                'end_time': '2024-01-01T00:00:05+00:00',
                'duration_seconds': 5.0,
                'providers': ['aws'], 'regions': ['us-east-1'],
                'checks_run': len(checks),
                'compliance_frameworks': ['CIS', 'SOC2'],
            },
            'summary': {
                'total_checks': len(all_findings),
                'passed': passed, 'failed': failed, 'errors': 0,
                'pass_rate': round(passed / max(len(all_findings), 1) * 100, 2),
                'by_severity': sev_counts,
                'by_provider': {'aws': failed},
                'by_category': {},
            },
            'risk_score': overall_score,
            'risk_level': risk_engine.score_to_level(overall_score),
            'findings': all_findings,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            builder = ReportBuilder(results, ['CIS', 'SOC2'])
            for fmt in ['json', 'html', 'csv']:
                path = builder.generate(fmt, os.path.join(tmpdir, 'report'))
                self.assertTrue(os.path.exists(path), f"{fmt} report not created")
                self.assertGreater(os.path.getsize(path), 100, f"{fmt} report is too small")


if __name__ == '__main__':
    unittest.main(verbosity=2)
