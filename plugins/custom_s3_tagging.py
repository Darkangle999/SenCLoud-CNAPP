"""
Odineyes Plugin Example — custom_s3_tagging.py
Drop this file in ~/.odineyes/plugins/ or ./plugins/
and it will be auto-loaded by Odineyes.

Run:  odineyes list-checks --search tagging
      odineyes scan --provider aws --checks custom_s3_001
"""

from typing import List, Dict, Any

# Import BaseCheck from the installed package
from odineyes.core.check_registry import BaseCheck
from odineyes.core.aws_session import shared_session


class S3BucketTaggingComplianceCheck(BaseCheck):
    """
    Example plugin: verifies that all S3 buckets have required
    governance tags (env, owner, cost-center).
    """
    check_id = "custom_s3_001"
    name = "S3 Bucket Required Tags Present"
    description = (
        "Ensures all S3 buckets have required governance tags: "
        "env, owner, cost-center"
    )
    provider = "aws"
    category = "storage"
    severity = "low"
    compliance = {
        "SOC2": ["CC2.1"],
        # ISO 27001:2022 A.5.9 — Inventory of information and other associated
        # assets (governance tags enable asset inventory/ownership). (A.8.1.1 was
        # the 2013 numbering.)
        "ISO27001": ["A.5.9"],
    }
    remediation = (
        "Add required tags to S3 buckets: "
        "aws s3api put-bucket-tagging --bucket <name> "
        "--tagging 'TagSet=[{Key=env,Value=prod},{Key=owner,Value=team}]'"
    )

    REQUIRED_TAGS = {"env", "owner", "cost-center"}

    def execute(self, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        try:
            import boto3
            session = shared_session(ctx.get("profile", "default"))
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])

            for bucket in buckets:
                name = bucket["Name"]
                try:
                    tag_response = s3.get_bucket_tagging(Bucket=name)
                    existing_tags = {
                        t["Key"].lower() for t in tag_response.get("TagSet", [])
                    }
                    missing = self.REQUIRED_TAGS - existing_tags
                    if missing:
                        findings.append(self._make_finding(
                            status="fail",
                            resource_id=f"arn:aws:s3:::{name}",
                            resource_type="s3:bucket",
                            region="global",
                            message=f"Bucket {name} missing required tags: {', '.join(sorted(missing))}",
                            metadata={"missing_tags": list(missing)},
                        ))
                    else:
                        findings.append(self._make_finding(
                            status="pass",
                            resource_id=f"arn:aws:s3:::{name}",
                            resource_type="s3:bucket",
                            region="global",
                            message=f"Bucket {name} has all required governance tags",
                        ))
                except s3.exceptions.ClientError:
                    # No tags at all
                    findings.append(self._make_finding(
                        status="fail",
                        resource_id=f"arn:aws:s3:::{name}",
                        resource_type="s3:bucket",
                        region="global",
                        message=f"Bucket {name} has NO tags — all required tags missing",
                        metadata={"missing_tags": list(self.REQUIRED_TAGS)},
                    ))
        except Exception:
            # Simulated output when no credentials
            for bname, tags in [
                ("prod-data", {"env", "owner"}),         # missing cost-center
                ("logs-bucket", set()),                   # missing all
                ("archive-2024", self.REQUIRED_TAGS),    # compliant
            ]:
                missing = self.REQUIRED_TAGS - tags
                findings.append(self._make_finding(
                    status="fail" if missing else "pass",
                    resource_id=f"arn:aws:s3:::{bname}",
                    resource_type="s3:bucket",
                    region="global",
                    message=(
                        f"[SIMULATED] Bucket {bname} missing tags: {', '.join(sorted(missing))}"
                        if missing else
                        f"[SIMULATED] Bucket {bname} has all required tags"
                    ),
                    metadata={"simulated": True, "missing_tags": list(missing)},
                ))
        return findings
