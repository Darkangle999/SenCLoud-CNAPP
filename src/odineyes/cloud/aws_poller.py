from __future__ import annotations
import boto3
from odineyes.cloud.models import (
    Ec2InstanceRecord,
    SecurityGroupRecord,
    IamCredentialRecord,
    RdsInstanceRecord
)

class AwsPoller:
    """
    Phase 3: The Cloud API Poller (AWS).
    Queries the AWS API to discover infrastructure context: 
    EC2 Instances, Security Groups, IAM Roles, and target resources like RDS.
    """

    def __init__(self, region: str, session: boto3.Session):
        self.region = region
        self.session = session
        self.ec2_client = self.session.client("ec2", region_name=self.region)
        self.iam_client = self.session.client("iam", region_name=self.region)
        self.rds_client = self.session.client("rds", region_name=self.region)

    def preflight_check(self):
        sts_client = self.session.client("sts", region_name=self.region)
        try:
            identity = sts_client.get_caller_identity()
            print(f"[*] AWS Preflight Check: Connected as {identity.get('Arn')} (Account: {identity.get('Account')})")
        except Exception as e:
            print(f"[!] AWS Preflight Check Failed: Could not get caller identity ({e})")

    def poll_ec2_instances(self) -> list[Ec2InstanceRecord]:
        try:
            response = self.ec2_client.describe_instances()
        except Exception:
            return []

        records = []
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                public_ip = instance.get("PublicIpAddress")
                tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
                
                records.append(Ec2InstanceRecord(
                    instance_id=instance.get("InstanceId", ""),
                    instance_type=instance.get("InstanceType", ""),
                    state=instance.get("State", {}).get("Name", ""),
                    private_ip=instance.get("PrivateIpAddress"),
                    public_ip=public_ip,
                    vpc_id=instance.get("VpcId", ""),
                    subnet_id=instance.get("SubnetId", ""),
                    image_id=instance.get("ImageId", ""),
                    tags=tags,
                    is_public=public_ip is not None
                ))
        return records

    def poll_security_groups(self) -> list[SecurityGroupRecord]:
        try:
            response = self.ec2_client.describe_security_groups()
        except Exception:
            return []

        records = []
        for sg in response.get("SecurityGroups", []):
            is_internet_exposed = False
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                if from_port in [22, 80, 443] or to_port in [22, 80, 443]:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            is_internet_exposed = True
                            break
                if is_internet_exposed:
                    break
                    
            records.append(SecurityGroupRecord(
                sg_id=sg.get("GroupId", ""),
                is_internet_exposed=is_internet_exposed
            ))
        return records

    def poll_iam_credentials(self) -> list[IamCredentialRecord]:
        try:
            response = self.iam_client.list_instance_profiles()
        except Exception:
            return []

        records = []
        for profile in response.get("InstanceProfiles", []):
            for role in profile.get("Roles", []):
                role_name = role.get("RoleName", "")
                has_admin = False
                
                try:
                    policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
                    for policy in policies.get("AttachedPolicies", []):
                        policy_name = policy.get("PolicyName", "")
                        if "Admin" in policy_name or "FullAccess" in policy_name:
                            has_admin = True
                            break
                except Exception:
                    pass
                    
                records.append(IamCredentialRecord(
                    role_name=role_name,
                    has_admin_policy=has_admin
                ))
        return records

    def poll_rds_instances(self) -> list[RdsInstanceRecord]:
        try:
            response = self.rds_client.describe_db_instances()
        except Exception:
            return []

        records = []
        for db in response.get("DBInstances", []):
            endpoint = db.get("Endpoint", {})
            records.append(RdsInstanceRecord(
                db_id=db.get("DBInstanceIdentifier", ""),
                engine=db.get("Engine", ""),
                endpoint_address=endpoint.get("Address", ""),
                vpc_id=db.get("DBSubnetGroup", {}).get("VpcId", ""),
                publicly_accessible=db.get("PubliclyAccessible", False)
            ))
        return records
