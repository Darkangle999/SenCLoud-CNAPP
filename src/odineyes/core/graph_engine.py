"""
Odineyes - Graph Correlation Engine
Correlates findings to identify toxic combinations.
"""

import uuid
from typing import List, Dict, Any
from datetime import datetime, timezone

class GraphEngine:
    """
    Analyzes raw findings to detect Toxic Combinations.
    """
    
    def __init__(self):
        self.rules = [
            self._rule_unprotected_public_data,
            self._rule_compromised_public_workload,
            self._rule_exposed_root_account,
        ]

    def correlate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run graph rules against findings to generate new Toxic Combination findings."""
        toxic_findings = []
        for rule in self.rules:
            result = rule(findings)
            if result:
                toxic_findings.extend(result)
        return toxic_findings

    def _rule_unprotected_public_data(self, findings: List[Dict]) -> List[Dict]:
        """
        Rule: S3 bucket is public AND unencrypted.
        """
        toxic = []
        # Group by resource_id
        bucket_findings = {}
        for f in findings:
            if f.get("status") == "fail" and f.get("resource_type") == "s3:bucket":
                res_id = f.get("resource_id")
                bucket_findings.setdefault(res_id, set()).add(f.get("check_id"))
        
        for res_id, checks in bucket_findings.items():
            # If both S3 Public Access (storage_aws_001) and Encryption (storage_aws_002) failed
            if "storage_aws_001" in checks and "storage_aws_002" in checks:
                toxic.append(self._make_toxic_finding(
                    name="Toxic Combination: Unprotected Public Data",
                    description="An S3 bucket is publicly accessible AND lacks default encryption, exposing it to severe data breaches.",
                    resource_id=res_id,
                    resource_type="s3:bucket",
                    region="global",
                    message="CRITICAL: Bucket is public and unencrypted.",
                    related_checks=["storage_aws_001", "storage_aws_002"]
                ))
        return toxic

    def _rule_compromised_public_workload(self, findings: List[Dict]) -> List[Dict]:
        """
        Rule: Malware/Secret found by Agentless Scanner AND Security Group allows Open SSH.
        For PoC: Checks globally if environment has both.
        """
        toxic = []
        has_malware = any(f.get("check_id") == "agentless_workload_001" and f.get("status") == "fail" for f in findings)
        has_open_ssh = any(f.get("check_id") == "network_aws_001" and f.get("status") == "fail" for f in findings)
        
        if has_malware and has_open_ssh:
            # Find the affected instance
            instance_id = next((f.get("resource_id") for f in findings if f.get("check_id") == "agentless_workload_001" and f.get("status") == "fail"), "unknown-instance")
            toxic.append(self._make_toxic_finding(
                name="Toxic Combination: Compromised Public Workload",
                description="A workload contains malware/secrets AND the environment allows open SSH (0.0.0.0/0).",
                resource_id=instance_id,
                resource_type="ec2:instance",
                region="global", # Can be extracted from findings
                message="CRITICAL: Workload has sensitive data/malware and is exposed to the internet via SSH.",
                related_checks=["agentless_workload_001", "network_aws_001"]
            ))
        return toxic

    def _rule_exposed_root_account(self, findings: List[Dict]) -> List[Dict]:
        """
        Rule: Root account lacks MFA AND has active access keys.
        """
        toxic = []
        root_failed_checks = {f.get("check_id") for f in findings 
                              if f.get("status") == "fail" and f.get("resource_id") == "root"}
        
        if "iam_aws_001" in root_failed_checks and "iam_aws_004" in root_failed_checks:
            toxic.append(self._make_toxic_finding(
                name="Toxic Combination: Exposed Root Account",
                description="Root account has NO MFA and ACTIVE access keys.",
                resource_id="root",
                resource_type="iam:root_account",
                region="global",
                message="CRITICAL: Root account is highly vulnerable.",
                related_checks=["iam_aws_001", "iam_aws_004"]
            ))
        return toxic

    def _make_toxic_finding(self, name: str, description: str, resource_id: str, 
                            resource_type: str, region: str, message: str, related_checks: List[str]) -> Dict:
        """Create a standardized Toxic Combination finding."""
        return {
            "check_id": f"toxic_{uuid.uuid4().hex[:8]}",
            "name": name,
            "description": description,
            "provider": "aws",
            "category": "toxic_combination",
            "severity": "critical",
            "status": "fail",
            "resource_id": resource_id,
            "resource_type": resource_type,
            "region": region,
            "message": f"🕸️ {message}",
            "remediation": "Fix the related misconfigurations to break the toxic combination.",
            "remediation_url": "",
            "references": [],
            "risk_weight": 3.0, # Highly weighted
            "metadata": {"toxic_combination": True, "related_checks": related_checks},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
