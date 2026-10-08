"""Phase 2 rules engine over the normalized inventory spine.

Rules read only the standard fields every normalizer guarantees (asset_type,
is_public, encryption_enabled, network_exposure, properties, relationships), so
they run identically over in-memory ``NormalizedAsset`` objects and persisted DB
``Asset`` rows — both expose the same attribute names. Pure and offline: no
cloud calls, deterministic, fixture-testable.

Two rule shapes:
  - single-asset rules (one asset -> 0..1 finding)
  - combination rules (the whole asset set -> toxic-combination findings)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol, runtime_checkable

from odineyes.inventory.reachability import build_network_topology
from odineyes.inventory.reachability_layers import assess_network_layer
from odineyes.inventory.tuning import apply_tuning

# Ports that are high-signal when reachable from the internet.
SENSITIVE_PORTS = {0: "ALL", 22: "SSH", 3389: "RDP", 3306: "MySQL",
                   5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
                   9200: "Elasticsearch", 23: "Telnet", 21: "FTP"}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Preventative controls remain visible, but do not compete with exploitable
# paths in product queues. A related workload exposure is raised by its own
# reachability/toxic-combination rule rather than inflating these hygiene facts.
NETWORK_HYGIENE_RULES = frozenset({
    "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED",
    "VPC_FLOW_LOGS_DISABLED",
    "UNUSED_SECURITY_GROUP",
})


def finding_signal(rule_id: str) -> str:
    return "network_hygiene" if rule_id in NETWORK_HYGIENE_RULES else "active_threat"

# rule_id -> compliance controls it evidences.
COMPLIANCE: dict[str, dict[str, list[str]]] = {
    "PUBLIC_ADMIN_ROLE": {"CIS": ["1.16"], "SOC2": ["CC6.1"], "NIST": ["AC-6", "AC-2"],
                          "PCI-DSS": ["7.1"], "ISO27001": ["A.5.15", "A.5.16"]},
    "WORLD_OPEN_SENSITIVE_PORT": {"CIS": ["5.2"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "SC-7"],
                                  "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "OVERLY_PERMISSIVE_CIDR": {"CIS": ["5.2"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "SC-7"],
                               "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "UNUSED_SECURITY_GROUP": {"CIS": ["5.4"], "SOC2": ["CC6.1"], "NIST": ["CM-8"],
                              "ISO27001": ["A.8.9"]},
    "RDS_PUBLIC_ENDPOINT_UNENCRYPTED": {"CIS": ["5.2"], "SOC2": ["CC6.1", "CC6.7"],
                                        "NIST": ["AC-3", "SC-7", "SC-28"], "PCI-DSS": ["1.3.1", "3.5"],
                                        "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.8.20", "A.8.24"]},
    "RDS_PUBLIC_ENDPOINT_CONFIGURED": {"CIS": ["5.2"], "SOC2": ["CC6.1", "CC6.7"], "NIST": ["AC-3", "SC-7"],
                                       "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "PUBLIC_BUCKET": {"CIS": ["2.1.1", "2.1.5"], "SOC2": ["CC6.1", "CC6.7"],
                      "NIST": ["AC-3", "SC-28"], "PCI-DSS": ["3.5"],
                      "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.8.3", "A.8.24"], "GDPR": ["Art.32"]},
    "UNENCRYPTED_DATABASE": {"CIS": ["2.3.1"], "SOC2": ["CC6.7"], "NIST": ["SC-28"],
                             "PCI-DSS": ["3.5"], "ISO27001": ["A.8.24"]},
    "PUBLIC_COMPUTE": {"CIS": ["5.2"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "SC-7"],
                       "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "PUBLIC_COMPUTE_TO_ADMIN": {"CIS": ["1.16", "5.2"], "SOC2": ["CC6.1"],
                                "NIST": ["AC-3", "AC-6"], "PCI-DSS": ["7.1"],
                                "ISO27001": ["A.5.15", "A.8.3"]},
    "PUBLIC_LAMBDA_URL": {"CIS": ["5.2"], "SOC2": ["CC6.1"], "NIST": ["AC-3", "SC-7"],
                          "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "PUBLIC_WAREHOUSE": {"CIS": ["5.2"], "SOC2": ["CC6.1", "CC6.7"],
                         "NIST": ["AC-3", "SC-7", "SC-28"], "PCI-DSS": ["1.3.1", "3.5"],
                         "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.8.20", "A.8.24"]},
    "CLOUDTRAIL_NOT_MULTIREGION": {"CIS": ["3.1"], "SOC2": ["CC7.2"], "NIST": ["AU-2", "AU-12"],
                                   "PCI-DSS": ["10.1"], "HIPAA": ["164.312(b)"], "ISO27001": ["A.8.15"]},
    "CLOUDTRAIL_NO_LOG_VALIDATION": {"CIS": ["3.2"], "SOC2": ["CC7.2"], "NIST": ["AU-9"],
                                     "PCI-DSS": ["10.5.2"], "ISO27001": ["A.8.15"]},
    "CLOUDTRAIL_NO_CLOUDWATCH": {"CIS": ["3.4"], "SOC2": ["CC7.2"], "NIST": ["AU-6"],
                                 "PCI-DSS": ["10.6"], "ISO27001": ["A.8.15"]},
    "CLOUDTRAIL_NOT_ENCRYPTED": {"CIS": ["3.7"], "SOC2": ["CC6.7"], "NIST": ["SC-28"],
                                 "PCI-DSS": ["3.5"], "ISO27001": ["A.8.24"]},
    "CLOUDTRAIL_S3_PUBLIC": {"CIS": ["3.3"], "SOC2": ["CC6.1", "CC7.2"], "NIST": ["AU-9", "AC-3"],
                             "PCI-DSS": ["10.5.1"], "ISO27001": ["A.8.15", "A.8.20"]},
    "CONFIG_NOT_ENABLED": {"CIS": ["2.5"], "SOC2": ["CC7.2"], "NIST": ["CM-8", "CM-3"],
                           "ISO27001": ["A.8.9"]},
    "KMS_KEY_ROTATION_DISABLED": {"CIS": ["2.8"], "SOC2": ["CC6.7"], "NIST": ["SC-12"],
                                  "ISO27001": ["A.8.24"]},
    "EBS_VOLUME_UNENCRYPTED": {"CIS": ["2.2.1"], "SOC2": ["CC6.7"], "NIST": ["SC-28"],
                               "PCI-DSS": ["3.5"], "HIPAA": ["164.312(a)(2)(iv)"],
                               "ISO27001": ["A.8.24"]},
    "EBS_SNAPSHOT_PUBLIC": {"CIS": ["2.2.1"], "SOC2": ["CC6.1", "CC6.7"],
                            "NIST": ["AC-3", "AC-21", "SC-28"], "PCI-DSS": ["1.3.1", "3.5"],
                            "HIPAA": ["164.312(a)(1)"], "ISO27001": ["A.5.14", "A.8.3"],
                            "GDPR": ["Art.32"]},
    "EBS_SNAPSHOT_UNENCRYPTED": {"CIS": ["2.2.1"], "SOC2": ["CC6.7"], "NIST": ["SC-28"],
                                 "PCI-DSS": ["3.5"], "ISO27001": ["A.8.24"]},
    "VPC_FLOW_LOGS_DISABLED": {"CIS": ["3.9"], "SOC2": ["CC7.2"], "NIST": ["AU-2", "AU-12", "SI-4"],
                               "PCI-DSS": ["10.1"], "ISO27001": ["A.8.15", "A.8.16"]},
    "EFS_UNENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"], "PCI-DSS": ["3.5"],
                        "HIPAA": ["164.312(a)(2)(iv)"], "ISO27001": ["A.8.24"]},
    "EFS_PUBLIC_POLICY": {"SOC2": ["CC6.1"], "NIST": ["AC-3", "AC-21"], "PCI-DSS": ["7.1"],
                          "ISO27001": ["A.5.15", "A.8.3"], "GDPR": ["Art.32"]},
    "SNS_TOPIC_PUBLIC_POLICY": {"SOC2": ["CC6.1"], "NIST": ["AC-3"], "PCI-DSS": ["7.1"],
                                "ISO27001": ["A.5.15", "A.8.3"]},
    "SNS_TOPIC_NOT_ENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"], "PCI-DSS": ["3.5"],
                                "ISO27001": ["A.8.24"]},
    "SQS_QUEUE_PUBLIC_POLICY": {"SOC2": ["CC6.1"], "NIST": ["AC-3"], "PCI-DSS": ["7.1"],
                                "ISO27001": ["A.5.15", "A.8.3"]},
    "SQS_QUEUE_NOT_ENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"], "PCI-DSS": ["3.5"],
                                "ISO27001": ["A.8.24"]},
    "DYNAMODB_PITR_DISABLED": {"SOC2": ["A1.2"], "NIST": ["CP-9", "CP-10"],
                               "ISO27001": ["A.8.13"]},
    "DYNAMODB_DELETION_PROTECTION_DISABLED": {"SOC2": ["A1.2"], "NIST": ["CP-9"],
                                              "ISO27001": ["A.8.13"]},
    "DYNAMODB_NOT_CMK_ENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-12", "SC-28"],
                                   "ISO27001": ["A.8.24"]},
    "APIGATEWAY_STAGE_LOGGING_DISABLED": {"SOC2": ["CC7.2"], "NIST": ["AU-2", "AU-12"],
                                          "PCI-DSS": ["10.1"], "ISO27001": ["A.8.15"]},
    "APIGATEWAY_STAGE_CACHE_UNENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"],
                                           "PCI-DSS": ["3.5"], "ISO27001": ["A.8.24"]},
    "GUARDDUTY_DETECTOR_DISABLED": {"SOC2": ["CC7.2"], "NIST": ["SI-4", "AU-6"],
                                    "PCI-DSS": ["11.5"], "ISO27001": ["A.8.16"]},
    "GUARDDUTY_NOT_ENABLED": {"SOC2": ["CC7.2"], "NIST": ["SI-4", "AU-6"],
                              "PCI-DSS": ["11.5"], "ISO27001": ["A.8.16"]},
    "ROOT_ACCOUNT_ACCESS_KEY": {"CIS": ["1.4"], "SOC2": ["CC6.1"],
                                "NIST": ["AC-6", "IA-5"], "PCI-DSS": ["8.3.9"],
                                "ISO27001": ["A.5.16", "A.5.17"]},
    "ROOT_ACCOUNT_MFA_DISABLED": {"CIS": ["1.5"], "SOC2": ["CC6.1"], "NIST": ["IA-2"],
                                  "PCI-DSS": ["8.4.2"], "ISO27001": ["A.5.17"]},
    "IAM_PASSWORD_POLICY_MISSING": {"CIS": ["1.8", "1.9"], "SOC2": ["CC6.1"],
                                    "NIST": ["IA-5"], "PCI-DSS": ["8.3.6"],
                                    "ISO27001": ["A.5.17"]},
    "IAM_PASSWORD_POLICY_WEAK": {"CIS": ["1.8", "1.9"], "SOC2": ["CC6.1"],
                                 "NIST": ["IA-5"], "PCI-DSS": ["8.3.6"],
                                 "ISO27001": ["A.5.17"]},
    "LOG_GROUP_NO_RETENTION": {"NIST": ["AU-11"], "ISO27001": ["A.8.15"]},
    "LOG_GROUP_NOT_ENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"], "ISO27001": ["A.8.24"]},
    "IAM_USER_PRIVILEGED_LONGLIVED_KEY": {"CIS": ["1.4", "1.14"], "SOC2": ["CC6.1"],
                                          "NIST": ["AC-2", "AC-6", "IA-5"], "PCI-DSS": ["8.3.9"],
                                          "ISO27001": ["A.5.16", "A.5.17"]},
    "IAM_USER_CONSOLE_NO_MFA": {"CIS": ["1.10"], "SOC2": ["CC6.1"], "NIST": ["IA-2"],
                                "PCI-DSS": ["8.4.2"], "ISO27001": ["A.5.17"]},
    "DORMANT_PRIVILEGED_IDENTITY": {"CIS": ["1.12", "1.13"], "SOC2": ["CC6.1"],
                                    "NIST": ["AC-2", "AC-6"], "PCI-DSS": ["8.1.4"],
                                    "ISO27001": ["A.5.18"]},
    "IDENTITY_UNRESTRICTED_ADMIN_GRANT": {
        "SOC2": ["CC6.1"], "NIST": ["AC-3", "AC-6"],
        "PCI-DSS": ["7.2.2"], "ISO27001": ["A.5.15", "A.8.2"],
    },
    "IDENTITY_PRIVILEGE_ESCALATION_GRANT": {
        "SOC2": ["CC6.1"], "NIST": ["AC-3", "AC-6"],
        "PCI-DSS": ["7.2.2"], "ISO27001": ["A.5.15", "A.8.2"],
    },
    "IAM_USER_DIRECT_POLICY_ATTACHMENT": {
        "SOC2": ["CC6.1"], "NIST": ["AC-2", "AC-6"],
        "PCI-DSS": ["7.2.2"], "ISO27001": ["A.5.16", "A.5.18"],
    },
    "S3_DEFAULT_ENCRYPTION_DISABLED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"],
                                       "PCI-DSS": ["3.5"], "HIPAA": ["164.312(a)(1)"],
                                       "ISO27001": ["A.8.24"], "GDPR": ["Art.32"]},
    "S3_VERSIONING_DISABLED": {"SOC2": ["CC7.4"], "NIST": ["CP-10"],
                               "ISO27001": ["A.8.13"]},
    "S3_ACCESS_LOGGING_DISABLED": {"SOC2": ["CC7.2"], "NIST": ["AU-2", "AU-12"],
                                    "PCI-DSS": ["10.2"], "ISO27001": ["A.8.15"]},
    "S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE": {"CIS": ["2.1.5"], "SOC2": ["CC6.1"],
                                          "NIST": ["AC-3", "SC-7"], "PCI-DSS": ["1.3.1"],
                                          "ISO27001": ["A.8.3"]},
    "EC2_IMDSV2_NOT_REQUIRED": {"SOC2": ["CC6.1"], "NIST": ["AC-3", "SI-10"],
                                "ISO27001": ["A.8.20"]},
    "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED": {"CIS": ["5.2"], "SOC2": ["CC6.1"],
                                             "NIST": ["SC-7"], "PCI-DSS": ["1.3.1"],
                                             "ISO27001": ["A.8.20"]},
    "DB_CLUSTER_UNENCRYPTED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"],
                               "PCI-DSS": ["3.5"], "HIPAA": ["164.312(a)(1)"],
                               "ISO27001": ["A.8.24"], "GDPR": ["Art.32"]},
    "DB_CLUSTER_DELETION_PROTECTION_DISABLED": {"SOC2": ["CC7.4"], "NIST": ["CP-10"],
                                                "ISO27001": ["A.8.13"]},
    "RDS_BACKUP_RETENTION_TOO_SHORT": {"SOC2": ["CC7.4"], "NIST": ["CP-9"],
                                       "ISO27001": ["A.8.13"]},
    "RDS_DELETION_PROTECTION_DISABLED": {"SOC2": ["CC7.4"], "NIST": ["CP-10"],
                                         "ISO27001": ["A.8.13"]},
    "RDS_PROXY_TLS_NOT_REQUIRED": {"SOC2": ["CC6.7"], "NIST": ["SC-8"],
                                   "PCI-DSS": ["4.2.1"], "HIPAA": ["164.312(e)(1)"],
                                   "ISO27001": ["A.8.24"], "GDPR": ["Art.32"]},
    "SECRET_ROTATION_DISABLED": {"SOC2": ["CC6.1"], "NIST": ["IA-5"],
                                 "PCI-DSS": ["8.3.9"], "ISO27001": ["A.5.17"]},
    "SECRET_PUBLIC_POLICY": {"SOC2": ["CC6.1"], "NIST": ["AC-3"],
                             "PCI-DSS": ["7.2"], "ISO27001": ["A.8.3"]},
    "ECS_CONTAINER_INSIGHTS_DISABLED": {"SOC2": ["CC7.2"], "NIST": ["AU-2", "AU-6"],
                                        "ISO27001": ["A.8.16"]},
    "ECS_TASK_DEFINITION_PRIVILEGED_CONTAINER": {"SOC2": ["CC6.1"], "NIST": ["AC-6", "CM-7"],
                                                  "PCI-DSS": ["7.2"], "ISO27001": ["A.8.2", "A.8.9"]},
    "ECS_TASK_DEFINITION_HOST_NETWORK": {"SOC2": ["CC6.1"], "NIST": ["SC-7", "CM-7"],
                                            "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "EKS_PUBLIC_ENDPOINT_UNRESTRICTED": {"SOC2": ["CC6.1"], "NIST": ["AC-3", "SC-7"],
                                           "PCI-DSS": ["1.3.1"], "ISO27001": ["A.8.20"]},
    "EKS_SECRETS_ENCRYPTION_DISABLED": {"SOC2": ["CC6.7"], "NIST": ["SC-28"],
                                          "PCI-DSS": ["3.5"], "ISO27001": ["A.8.24"]},
    "ECR_IMAGE_SCANNING_DISABLED": {"SOC2": ["CC7.1"], "NIST": ["RA-5", "SI-2"],
                                      "PCI-DSS": ["6.3.3"], "ISO27001": ["A.8.8"]},
    "ECR_UNRESTRICTED_REPOSITORY_POLICY": {"SOC2": ["CC6.1"], "NIST": ["AC-3"],
                                             "PCI-DSS": ["7.2"], "ISO27001": ["A.8.3"]},
    "ECR_LIFECYCLE_POLICY_MISSING": {"SOC2": ["CC7.4"], "NIST": ["CM-8"],
                                       "ISO27001": ["A.8.9"]},
    "CLOUDTRAIL_NOT_LOGGING": {"CIS": ["3.1"], "SOC2": ["CC7.2"],
                               "NIST": ["AU-2", "AU-12"], "PCI-DSS": ["10.2"],
                               "HIPAA": ["164.312(b)"], "ISO27001": ["A.8.15"]},
    "KMS_KEY_PENDING_DELETION": {"SOC2": ["CC6.7"], "NIST": ["SC-12"],
                                 "ISO27001": ["A.8.24"]},
}

# Built-in policy inventory. The evaluator remains ordinary Python functions;
# this catalog makes coverage queryable without introducing a second rule DSL.
# Severity is the maximum a rule emits when context can elevate it.
_POLICY_GROUPS: tuple[tuple[str, str, tuple[str, ...], dict[str, str]], ...] = (
    ("iam", "identity", ("aws.iam.role", "aws.iam.user"), {
        "PUBLIC_ADMIN_ROLE": "critical",
        "IAM_USER_PRIVILEGED_LONGLIVED_KEY": "critical",
        "IAM_USER_CONSOLE_NO_MFA": "high",
        "DORMANT_PRIVILEGED_IDENTITY": "high",
        "IDENTITY_UNRESTRICTED_ADMIN_GRANT": "high",
        "IDENTITY_PRIVILEGE_ESCALATION_GRANT": "high",
        "IAM_USER_DIRECT_POLICY_ATTACHMENT": "medium",
    }),
    ("ec2", "network", ("aws.ec2.security_group", "aws.ec2.subnet"), {
        "WORLD_OPEN_SENSITIVE_PORT": "high",
        "OVERLY_PERMISSIVE_CIDR": "high",
        "UNUSED_SECURITY_GROUP": "low",
        "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED": "medium",
    }),
    ("ec2", "compute", ("aws.ec2.instance",), {
        "PUBLIC_COMPUTE": "medium",
        "EC2_IMDSV2_NOT_REQUIRED": "high",
        "PUBLIC_COMPUTE_TO_ADMIN": "critical",
    }),
    ("s3", "data", ("aws.s3.bucket",), {
        "PUBLIC_BUCKET": "high",
        "S3_DEFAULT_ENCRYPTION_DISABLED": "medium",
        "S3_VERSIONING_DISABLED": "low",
        "S3_ACCESS_LOGGING_DISABLED": "low",
        "S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE": "medium",
    }),
    ("rds", "data", (
        "aws.rds.db_instance", "aws.rds.db_cluster", "aws.rds.db_proxy",
        "aws.neptune.cluster", "aws.docdb.cluster",
    ), {
        "RDS_PUBLIC_ENDPOINT_UNENCRYPTED": "high",
        "RDS_PUBLIC_ENDPOINT_CONFIGURED": "medium",
        "UNENCRYPTED_DATABASE": "medium",
        "DB_CLUSTER_UNENCRYPTED": "high",
        "DB_CLUSTER_DELETION_PROTECTION_DISABLED": "low",
        "RDS_BACKUP_RETENTION_TOO_SHORT": "medium",
        "RDS_DELETION_PROTECTION_DISABLED": "low",
        "RDS_PROXY_TLS_NOT_REQUIRED": "high",
    }),
    ("lambda", "compute", ("aws.lambda.function",), {
        "PUBLIC_LAMBDA_URL": "high",
    }),
    ("redshift", "data", ("aws.redshift.cluster",), {
        "PUBLIC_WAREHOUSE": "critical",
    }),
    ("secretsmanager", "data", ("aws.secretsmanager.secret",), {
        "SECRET_ROTATION_DISABLED": "low",
        "SECRET_PUBLIC_POLICY": "high",
    }),
    ("ecs", "compute", ("aws.ecs.cluster", "aws.ecs.task_definition"), {
        "ECS_CONTAINER_INSIGHTS_DISABLED": "low",
        "ECS_TASK_DEFINITION_PRIVILEGED_CONTAINER": "high",
        "ECS_TASK_DEFINITION_HOST_NETWORK": "high",
    }),
    ("eks", "compute", ("aws.eks.cluster",), {
        "EKS_PUBLIC_ENDPOINT_UNRESTRICTED": "high",
        "EKS_SECRETS_ENCRYPTION_DISABLED": "medium",
    }),
    ("ecr", "application", ("aws.ecr.repository",), {
        "ECR_IMAGE_SCANNING_DISABLED": "medium",
        "ECR_UNRESTRICTED_REPOSITORY_POLICY": "medium",
        "ECR_LIFECYCLE_POLICY_MISSING": "low",
    }),
    ("cloudtrail", "management", ("aws.cloudtrail.trail", "aws.s3.bucket"), {
        "CLOUDTRAIL_NOT_LOGGING": "high",
        "CLOUDTRAIL_NOT_MULTIREGION": "high",
        "CLOUDTRAIL_NO_LOG_VALIDATION": "medium",
        "CLOUDTRAIL_NO_CLOUDWATCH": "medium",
        "CLOUDTRAIL_NOT_ENCRYPTED": "high",
        "CLOUDTRAIL_S3_PUBLIC": "critical",
    }),
    ("config", "management", ("aws.config.recorder",), {
        "CONFIG_NOT_ENABLED": "high",
    }),
    ("kms", "data", ("aws.kms.key",), {
        "KMS_KEY_ROTATION_DISABLED": "medium",
        "KMS_KEY_PENDING_DELETION": "high",
    }),
    ("cloudwatch", "management", ("aws.cloudwatch.log_group",), {
        "LOG_GROUP_NO_RETENTION": "low",
        "LOG_GROUP_NOT_ENCRYPTED": "medium",
    }),
    ("ebs", "data", ("aws.ec2.volume", "aws.ec2.snapshot"), {
        "EBS_VOLUME_UNENCRYPTED": "medium",
        "EBS_SNAPSHOT_PUBLIC": "critical",
        "EBS_SNAPSHOT_UNENCRYPTED": "medium",
    }),
    ("vpc", "network", ("aws.ec2.vpc",), {
        "VPC_FLOW_LOGS_DISABLED": "medium",
    }),
    ("efs", "data", ("aws.efs.file_system",), {
        "EFS_UNENCRYPTED": "high",
        "EFS_PUBLIC_POLICY": "critical",
    }),
    ("sns", "data", ("aws.sns.topic",), {
        "SNS_TOPIC_PUBLIC_POLICY": "high",
        "SNS_TOPIC_NOT_ENCRYPTED": "medium",
    }),
    ("sqs", "data", ("aws.sqs.queue",), {
        "SQS_QUEUE_PUBLIC_POLICY": "high",
        "SQS_QUEUE_NOT_ENCRYPTED": "medium",
    }),
    ("dynamodb", "data", ("aws.dynamodb.table",), {
        "DYNAMODB_PITR_DISABLED": "medium",
        "DYNAMODB_DELETION_PROTECTION_DISABLED": "low",
        "DYNAMODB_NOT_CMK_ENCRYPTED": "low",
    }),
    ("apigateway", "network", ("aws.apigateway.rest_api",), {
        "APIGATEWAY_STAGE_LOGGING_DISABLED": "medium",
        "APIGATEWAY_STAGE_CACHE_UNENCRYPTED": "medium",
    }),
    ("guardduty", "management", ("aws.guardduty.detector", "aws.iam.account_settings"), {
        "GUARDDUTY_DETECTOR_DISABLED": "high",
        "GUARDDUTY_NOT_ENABLED": "high",
    }),
    ("iam", "identity", ("aws.iam.account_settings",), {
        "ROOT_ACCOUNT_ACCESS_KEY": "critical",
        "ROOT_ACCOUNT_MFA_DISABLED": "critical",
        "IAM_PASSWORD_POLICY_MISSING": "medium",
        "IAM_PASSWORD_POLICY_WEAK": "medium",
    }),
)

_RELATIONSHIP_POLICIES = {
    "WORLD_OPEN_SENSITIVE_PORT",
    "PUBLIC_COMPUTE_TO_ADMIN",
    "UNUSED_SECURITY_GROUP",
    "CLOUDTRAIL_NOT_MULTIREGION",
    "CLOUDTRAIL_S3_PUBLIC",
    "GUARDDUTY_NOT_ENABLED",
}
_EVIDENCE_GATED_POLICIES = {
    "S3_DEFAULT_ENCRYPTION_DISABLED",
    "S3_VERSIONING_DISABLED",
    "S3_ACCESS_LOGGING_DISABLED",
    "S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE",
    "SECRET_PUBLIC_POLICY",
    "CLOUDTRAIL_NOT_LOGGING",
    "CONFIG_NOT_ENABLED",
    "EBS_SNAPSHOT_PUBLIC",
    "VPC_FLOW_LOGS_DISABLED",
    "EFS_PUBLIC_POLICY",
    "SNS_TOPIC_PUBLIC_POLICY",
    "SNS_TOPIC_NOT_ENCRYPTED",
    "SQS_QUEUE_PUBLIC_POLICY",
    "SQS_QUEUE_NOT_ENCRYPTED",
    "DYNAMODB_PITR_DISABLED",
    "APIGATEWAY_STAGE_LOGGING_DISABLED",
    "APIGATEWAY_STAGE_CACHE_UNENCRYPTED",
    "ROOT_ACCOUNT_ACCESS_KEY",
    "ROOT_ACCOUNT_MFA_DISABLED",
    "IAM_PASSWORD_POLICY_MISSING",
    "IAM_PASSWORD_POLICY_WEAK",
}


def _policy_title(rule_id: str) -> str:
    title = rule_id.replace("_", " ").title()
    for source, target in (
        ("Iam", "IAM"), ("Ec2", "EC2"), ("Imdsv2", "IMDSv2"),
        ("S3", "S3"), ("Rds", "RDS"), ("Tls", "TLS"),
        ("Ecs", "ECS"), ("Kms", "KMS"), ("Ebs", "EBS"),
        ("Efs", "EFS"), ("Sns", "SNS"), ("Sqs", "SQS"),
        ("Vpc", "VPC"), ("Dynamodb", "DynamoDB"), ("Pitr", "PITR"),
        ("Cmk", "CMK"), ("Apigateway", "API Gateway"), ("Guardduty", "GuardDuty"),
        ("Mfa", "MFA"),
    ):
        title = title.replace(source, target)
    return title


def builtin_policy_catalog() -> list[dict[str, Any]]:
    """Machine-readable inventory of every persisted built-in policy."""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for service, category, asset_types, policies in _POLICY_GROUPS:
        for rule_id, severity in policies.items():
            if rule_id in seen:
                raise RuntimeError(f"duplicate built-in policy metadata: {rule_id}")
            seen.add(rule_id)
            items.append({
                "policy_id": rule_id,
                "title": _policy_title(rule_id),
                "provider": "aws",
                "service": service,
                "category": category,
                "asset_types": list(asset_types),
                "maximum_severity": severity,
                "evaluation_mode": (
                    "relationship" if rule_id in _RELATIONSHIP_POLICIES else "resource"
                ),
                "evidence_gated": rule_id in _EVIDENCE_GATED_POLICIES,
                "compliance": COMPLIANCE.get(rule_id, {}),
                "enabled": True,
            })
    missing = set(COMPLIANCE) - seen
    extra = seen - set(COMPLIANCE)
    if missing or extra:
        raise RuntimeError(
            f"built-in policy catalog mismatch: missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return sorted(items, key=lambda item: (item["service"], item["policy_id"]))

# An identity unused for this many days (or never used since creation) is
# treated as dormant. Dormant + privileged = standing attack surface nobody
# watches. ponytail: flat threshold; per-account config if teams keep
# deliberately-idle break-glass roles.
_DORMANT_DAYS = 90

# An access key older than this (days) that is still active on a privileged user
# is treated as a leaked-credential risk. ponytail: flat threshold; make it
# per-account config if a team has a documented longer rotation window.
_KEY_MAX_AGE_DAYS = 90


# rule_id -> copy-paste AWS CLI fix, templated on {name} (the resource's short
# name: role name / bucket / sg-id / db identifier). Only rules with a SAFE
# one-liner appear here; fixes needing human judgement (re-architecting a public
# EC2, rotating encryption via snapshot+restore) are deliberately absent so we
# never hand an operator a destructive command to paste blind.
REMEDIATION_CLI: dict[str, str] = {
    "PUBLIC_ADMIN_ROLE":
        "aws iam detach-role-policy --role-name {name} "
        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "WORLD_OPEN_SENSITIVE_PORT":
        "aws ec2 revoke-security-group-ingress --group-id {name} "
        "--protocol tcp --port <PORT> --cidr 0.0.0.0/0",
    "RDS_PUBLIC_ENDPOINT_UNENCRYPTED":
        "aws rds modify-db-instance --db-instance-identifier {name} "
        "--no-publicly-accessible --apply-immediately",
    "RDS_PUBLIC_ENDPOINT_CONFIGURED":
        "aws rds modify-db-instance --db-instance-identifier {name} "
        "--no-publicly-accessible --apply-immediately",
    "PUBLIC_BUCKET":
        "aws s3api put-public-access-block --bucket {name} "
        "--public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    "PUBLIC_LAMBDA_URL":
        "aws lambda update-function-url-config --function-name {name} --auth-type AWS_IAM",
    "PUBLIC_WAREHOUSE":
        "aws redshift modify-cluster --cluster-identifier {name} --no-publicly-accessible",
    "CLOUDTRAIL_NOT_MULTIREGION":
        "aws cloudtrail update-trail --name {name} --is-multi-region-trail",
    "CLOUDTRAIL_NO_LOG_VALIDATION":
        "aws cloudtrail update-trail --name {name} --enable-log-file-validation",
    "CONFIG_NOT_ENABLED":
        "aws configservice start-configuration-recorder --configuration-recorder-name {name}",
    "LOG_GROUP_NO_RETENTION":
        "aws logs put-retention-policy --log-group-name {name} --retention-in-days 365",
    "IAM_USER_CONSOLE_NO_MFA":
        "aws iam list-mfa-devices --user-name {name}  # then enrol an MFA device for this user",
}


def _short_name(resource_id: str) -> str:
    """Last meaningful segment of an ARN / resource id — the value AWS CLI wants
    (role name, bucket, sg-id, db identifier). ``arn:aws:iam::1:role/x/Name`` ->
    ``Name``; ``sg-abc`` -> ``sg-abc``; ``my-bucket`` -> ``my-bucket``."""
    tail = resource_id.split(":")[-1]
    return tail.split("/")[-1] or tail


def remediation_command(rule_id: str, resource_id: str) -> str:
    """Best-effort copy-paste AWS CLI fix for a finding, or "" when the fix needs
    human judgement. ponytail: <PORT> stays a placeholder — the persisted Finding
    row doesn't carry the offending port; the operator fills it from the SG rule."""
    tmpl = REMEDIATION_CLI.get(rule_id)
    return tmpl.format(name=_short_name(resource_id)) if tmpl else ""


@runtime_checkable
class AssetLike(Protocol):
    resource_id: str
    asset_type: str
    is_public: bool
    encryption_enabled: Any
    network_exposure: str
    properties: dict[str, Any]
    relationships: list[dict[str, Any]]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str                       # critical | high | medium | low
    resource_id: str
    asset_type: str
    why: str
    remediation: str
    compliance: dict[str, list[str]] = field(default_factory=dict)
    related: list[str] = field(default_factory=list)  # other resource_ids in a combo
    # Set by inventory/tuning.py when the detection is true but not actionable.
    # "" means it alerts. Kept on the finding rather than dropped so that "why
    # did you not tell me about this" has an answer.
    suppressed_by: str = ""             # path | managed | intent | data
    suppressed_why: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "resource_id": self.resource_id, "asset_type": self.asset_type,
            "why": self.why, "remediation": self.remediation,
            "compliance": self.compliance, "related": self.related,
            "suppressed_by": self.suppressed_by, "suppressed_why": self.suppressed_why,
        }


def _finding(rule_id: str, title: str, severity: str, asset: AssetLike,
             why: str, remediation: str, related: list[str] | None = None) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity,
        resource_id=asset.resource_id, asset_type=asset.asset_type,
        why=why, remediation=remediation,
        compliance=COMPLIANCE.get(rule_id, {}), related=related or [],
    )


# ── single-asset rules ─────────────────────────────────────────

def rule_public_admin_role(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.iam.role":
        return None
    if asset.is_public and asset.properties.get("has_admin"):
        return _finding(
            "PUBLIC_ADMIN_ROLE", "Publicly-assumable role with admin privileges", "critical",
            asset,
            why=("Role trusts a wildcard principal and carries admin-level permissions "
                 f"({asset.properties.get('admin_reason') or 'admin policy'}). Anyone who "
                 "can assume it controls the account."),
            remediation="Scope the AssumeRolePolicy trust to known principals and remove admin grants.",
        )
    return None


def rule_identity_unrestricted_admin_grant(asset: AssetLike) -> Finding | None:
    """An identity policy contains an unconditional Action/Resource wildcard."""
    if asset.asset_type not in ("aws.iam.role", "aws.iam.user"):
        return None
    properties = asset.properties
    if not properties.get("has_admin_grant"):
        return None
    bounded = bool(properties.get("boundary_restricts_admin"))
    source = properties.get("admin_reason") or "an identity policy"
    boundary_note = (
        " A permissions boundary currently prevents the full admin capability, "
        "but the underlying grant remains dangerous if that boundary changes."
        if bounded else ""
    )
    return _finding(
        "IDENTITY_UNRESTRICTED_ADMIN_GRANT",
        "Identity policy grants unrestricted administrator access",
        "medium" if bounded else "high",
        asset,
        why=(
            f"{source} contains an unconditional Allow with Action '*' and "
            f"Resource '*'.{boundary_note}"
        ),
        remediation=(
            "Replace the wildcard administrator statement with task-specific "
            "actions and resources; retain a boundary as defense in depth."
        ),
    )


def rule_identity_privilege_escalation_grant(asset: AssetLike) -> Finding | None:
    """An identity can modify privilege or obtain another role under our scope."""
    if asset.asset_type not in ("aws.iam.role", "aws.iam.user"):
        return None
    properties = asset.properties
    actions = properties.get("effective_privesc_actions")
    if actions is None:
        actions = properties.get("privesc_actions") or []
    actions = [str(action) for action in actions]
    if not actions:
        return None
    displayed = ", ".join(actions[:6])
    remainder = f" and {len(actions) - 6} more" if len(actions) > 6 else ""
    return _finding(
        "IDENTITY_PRIVILEGE_ESCALATION_GRANT",
        "Identity policy grants a privilege-escalation capability",
        "high",
        asset,
        why=(
            "Identity-policy and permissions-boundary evidence permits "
            f"{displayed}{remainder}. These actions can change privilege or "
            "reach another role; organization and session policies are not yet "
            "evaluated, so this is a capability candidate rather than a claim "
            "about every possible request."
        ),
        remediation=(
            "Remove the escalation action, scope it to approved resources and "
            "conditions, or constrain it with a permissions boundary and SCP."
        ),
    )


def rule_iam_user_direct_policy_attachment(asset: AssetLike) -> Finding | None:
    """Direct user policy grants complicate review and lifecycle management."""
    if asset.asset_type != "aws.iam.user":
        return None
    count = int(asset.properties.get("direct_policy_count") or 0)
    if count <= 0:
        return None
    return _finding(
        "IAM_USER_DIRECT_POLICY_ATTACHMENT",
        "IAM user receives permissions from a directly attached policy",
        "medium",
        asset,
        why=(
            f"User has {count} direct policy source{'s' if count != 1 else ''}. "
            "Direct grants are harder to review and revoke consistently than "
            "group membership or temporary role-based access."
        ),
        remediation=(
            "Move reusable permissions to an IAM group or, preferably, federated "
            "role-based access; then remove the direct user policy."
        ),
    )


def rule_iam_user_privileged_longlived_key(asset: AssetLike) -> Finding | None:
    """A privileged IAM user (admin or privilege-escalation grants) carrying an
    active access key older than the rotation window. Roles hand out temporary
    STS creds; a user's long-lived key is what leaks in a git commit or CI log
    and hands an attacker standing, privileged access."""
    if asset.asset_type != "aws.iam.user":
        return None
    p = asset.properties
    privesc = p.get("effective_privesc_actions")
    if privesc is None:
        privesc = p.get("privesc_actions")
    privileged = bool(p.get("has_admin")) or bool(privesc)
    age = int(p.get("access_key_max_age_days") or 0)
    if privileged and p.get("access_key_active") and age > _KEY_MAX_AGE_DAYS:
        grant = p.get("admin_reason") or "privilege-escalation permissions"
        return _finding(
            "IAM_USER_PRIVILEGED_LONGLIVED_KEY",
            "Privileged IAM user with a long-lived active access key", "critical",
            asset,
            why=(f"User has {grant} and an active access key {age} days old "
                 f"(> {_KEY_MAX_AGE_DAYS}). A leaked key grants standing privileged "
                 "access with no MFA and no expiry."),
            remediation=("Rotate then deactivate the old key; move the workload to a "
                         "role with temporary credentials and remove the standing grants."),
        )
    return None


def rule_iam_user_console_no_mfa(asset: AssetLike) -> Finding | None:
    """A console-login IAM user without an MFA device — credential-stuffing and
    phishing land directly on the account."""
    if asset.asset_type != "aws.iam.user":
        return None
    p = asset.properties
    if p.get("console_enabled") and not p.get("mfa_enabled"):
        return _finding(
            "IAM_USER_CONSOLE_NO_MFA",
            "IAM user has console access without MFA", "high", asset,
            why=("User can sign in to the AWS console but has no MFA device. A "
                 "phished or reused password is enough to take over the identity."),
            remediation="Enrol a virtual or hardware MFA device for this user (or disable console access).",
        )
    return None


def rule_dormant_privileged_identity(asset: AssetLike) -> Finding | None:
    """A privileged IAM role or user that is dormant — unused past the window, or
    never used since creation. Unused privilege is pure attack surface: no owner
    is watching it, but a leaked key / assumable trust still grants full access."""
    if asset.asset_type not in ("aws.iam.role", "aws.iam.user"):
        return None
    p = asset.properties
    privesc = p.get("effective_privesc_actions")
    if privesc is None:
        privesc = p.get("privesc_actions")
    if not (p.get("has_admin") or privesc):
        return None
    last = p.get("last_used_days")
    age = p.get("age_days")
    if last is not None and last > _DORMANT_DAYS:
        when = f"last used {last} days ago"
    elif last is None and age is not None and age > _DORMANT_DAYS:
        when = f"never used since it was created {age} days ago"
    else:
        return None  # active, or too new to call dormant
    kind = "role" if asset.asset_type == "aws.iam.role" else "user"
    grant = p.get("admin_reason") or "privilege-escalation permissions"
    return _finding(
        "DORMANT_PRIVILEGED_IDENTITY", "Dormant privileged identity", "high", asset,
        why=(f"IAM {kind} holds {grant} but was {when}. Unused privilege is standing "
             "attack surface — a leaked key or an over-broad trust still grants access, "
             "with no owner watching the identity."),
        remediation="Remove the privileged grants, or delete the identity if it is no longer needed.",
    )


def rule_overly_permissive_cidr(asset: AssetLike) -> Finding | None:
    """SG ingress from a broad *public* CIDR (wider than /16) that isn't the
    catch-all 0.0.0.0/0. `0.0.0.0/0` is covered by WORLD_OPEN_SENSITIVE_PORT;
    this catches the near-miss (e.g. a /8) that still exposes millions of hosts."""
    if asset.asset_type != "aws.ec2.security_group":
        return None
    wide = asset.properties.get("wide_open_cidrs") or []
    if not wide:
        return None
    # Report the broadest range (smallest prefix number) first.
    widest = min(wide, key=lambda c: c.get("prefix", 32))
    cidrs = ", ".join(sorted({str(c.get("cidr")) for c in wide}))
    return _finding(
        "OVERLY_PERMISSIVE_CIDR", "Security group allows a broad public CIDR", "high", asset,
        why=(f"Ingress permits {cidrs} (broadest /{widest.get('prefix')}), a public range "
             f"far wider than a host or office — millions of internet addresses reach the port."),
        remediation="Narrow the ingress CIDR to the specific trusted address range.",
    )


def rule_public_unencrypted_db(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.rds.db_instance":
        return None
    if _rds_public_endpoint(asset) and asset.encryption_enabled is False:
        return _finding(
            "RDS_PUBLIC_ENDPOINT_UNENCRYPTED", "RDS public endpoint configured without storage encryption",
            "high", asset,
            why=("RDS has PubliclyAccessible enabled and storage encryption is disabled. "
                 "This is configuration risk; it is not labelled internet-reachable until network-path evidence is collected."),
            remediation="Disable PubliclyAccessible when not required and enable storage encryption with KMS.",
        )
    return None


def rule_public_database(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.rds.db_instance":
        return None
    # Skip if the stronger public+unencrypted rule already fires.
    if _rds_public_endpoint(asset) and asset.encryption_enabled is not False:
        return _finding(
            "RDS_PUBLIC_ENDPOINT_CONFIGURED", "RDS public endpoint is configured", "medium", asset,
            why=("PubliclyAccessible is enabled. Security groups, routes, internet gateways and network ACLs "
                 "must still be evaluated before this becomes an internet-reachable attack path."),
            remediation="If public access is unnecessary, disable PubliclyAccessible and use private subnets or controlled access paths.",
        )
    return None


def rule_unencrypted_database(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.rds.db_instance":
        return None
    if not _rds_public_endpoint(asset) and asset.encryption_enabled is False:
        return _finding(
            "UNENCRYPTED_DATABASE", "Database storage is unencrypted", "medium", asset,
            why="Storage encryption is disabled; data at rest is unprotected.",
            remediation="Enable storage encryption (KMS) on the instance.",
        )
    return None


def _rds_public_endpoint(asset: AssetLike) -> bool:
    """RDS configuration with backwards compatibility for pre-migration assets."""
    return bool(asset.properties.get("publicly_accessible", asset.is_public))


def _facet_known(asset: AssetLike, facet: str) -> bool:
    """Whether an enrichment facet was actually observed or proven absent."""
    state = (asset.properties.get("collection_evidence") or {}).get(facet)
    return state in {"observed", "absent"}


def rule_public_bucket(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.s3.bucket":
        return None
    if asset.is_public:
        return _finding(
            "PUBLIC_BUCKET", "Publicly-accessible S3 bucket", "high", asset,
            why="Bucket policy or ACL grants public access; objects may be world-readable.",
            remediation="Enable Block Public Access and remove public policy/ACL grants.",
        )
    return None


def rule_s3_default_encryption_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.s3.bucket" or not _facet_known(asset, "encryption"):
        return None
    if asset.encryption_enabled is False:
        return _finding(
            "S3_DEFAULT_ENCRYPTION_DISABLED", "S3 bucket default encryption is disabled",
            "medium", asset,
            why="The bucket has no observed default server-side encryption configuration.",
            remediation="Configure default SSE-S3 or SSE-KMS encryption for new objects.",
        )
    return None


def rule_s3_versioning_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.s3.bucket" or not _facet_known(asset, "versioning"):
        return None
    if asset.properties.get("versioning") != "Enabled":
        return _finding(
            "S3_VERSIONING_DISABLED", "S3 bucket versioning is not enabled", "low", asset,
            why="Deleted or overwritten objects cannot be reliably recovered through S3 object versions.",
            remediation="Enable S3 Versioning and define lifecycle rules for noncurrent versions.",
        )
    return None


def rule_s3_access_logging_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.s3.bucket" or not _facet_known(asset, "logging"):
        return None
    if asset.properties.get("logging_enabled") is False:
        return _finding(
            "S3_ACCESS_LOGGING_DISABLED", "S3 server access logging is disabled", "low", asset,
            why="The bucket does not produce server access logs for object-level request investigations.",
            remediation="Enable server access logging to a separate, protected logging bucket.",
        )
    return None


def rule_s3_public_access_block_incomplete(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.s3.bucket" or not _facet_known(asset, "public_access_block"):
        return None
    settings = asset.properties.get("block_public_access") or {}
    required = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
    missing = [name for name in required if settings.get(name) is not True]
    if missing:
        return _finding(
            "S3_PUBLIC_ACCESS_BLOCK_INCOMPLETE", "S3 Block Public Access is incomplete",
            "medium", asset,
            why=f"Bucket-level protection is missing or disabled for: {', '.join(missing)}.",
            remediation="Enable all four S3 Block Public Access settings on the bucket.",
        )
    return None


def rule_public_compute(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.instance":
        return None
    if asset.is_public:
        return _finding(
            "PUBLIC_COMPUTE", "Internet-facing compute instance", "medium", asset,
            why="Instance has a public IP and is directly reachable from the internet.",
            remediation="Remove the public IP or front the instance with a load balancer in a private subnet.",
        )
    return None


def rule_ec2_imdsv2_not_required(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.instance":
        return None
    if asset.properties.get("metadata_http_tokens") == "optional":
        severity = "high" if asset.is_public else "medium"
        return _finding(
            "EC2_IMDSV2_NOT_REQUIRED", "EC2 instance does not require IMDSv2",
            severity, asset,
            why="IMDSv1 requests are accepted, increasing credential-theft risk through SSRF or compromised software.",
            remediation="Set MetadataOptions.HttpTokens to required after validating workload compatibility.",
        )
    return None


def rule_subnet_auto_assign_public_ip_enabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.subnet":
        return None
    if asset.properties.get("map_public_ip_on_launch") is True:
        return _finding(
            "SUBNET_AUTO_ASSIGN_PUBLIC_IP_ENABLED",
            "Subnet automatically assigns public IPv4 addresses", "medium", asset,
            why="New instances launched in this subnet receive public addresses by default, expanding accidental exposure risk.",
            remediation="Disable MapPublicIpOnLaunch and explicitly assign public connectivity only where required.",
        )
    return None


def rule_public_lambda(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.lambda.function":
        return None
    if asset.is_public:
        cause = ("an unauthenticated function URL" if asset.properties.get("function_url_auth") == "NONE"
                 else "a resource policy trusting any principal")
        return _finding(
            "PUBLIC_LAMBDA_URL", "Lambda function invocable without authentication", "high",
            asset,
            why=f"Function is exposed through {cause}; anyone on the internet can invoke it.",
            remediation="Set the function URL AuthType to AWS_IAM (or remove it) and scope the resource policy.",
        )
    return None


def rule_db_cluster_unencrypted(asset: AssetLike) -> Finding | None:
    cluster_types = {"aws.rds.db_cluster", "aws.neptune.cluster", "aws.docdb.cluster"}
    if asset.asset_type not in cluster_types:
        return None
    if asset.encryption_enabled is False:
        return _finding(
            "DB_CLUSTER_UNENCRYPTED", "Database cluster storage is unencrypted",
            "high", asset,
            why="The database cluster does not have storage encryption enabled.",
            remediation="Migrate the cluster to an encrypted snapshot or encrypted replacement using a KMS key.",
        )
    return None


def rule_db_cluster_deletion_protection_disabled(asset: AssetLike) -> Finding | None:
    cluster_types = {"aws.rds.db_cluster", "aws.neptune.cluster", "aws.docdb.cluster"}
    if asset.asset_type not in cluster_types:
        return None
    if asset.properties.get("deletion_protection") is False:
        return _finding(
            "DB_CLUSTER_DELETION_PROTECTION_DISABLED",
            "Database cluster deletion protection is disabled", "low", asset,
            why="An accidental or malicious delete operation can remove the cluster without the deletion-protection guard.",
            remediation="Enable deletion protection for persistent or production database clusters.",
        )
    return None


def rule_rds_backup_retention_too_short(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.rds.db_instance":
        return None
    retention = asset.properties.get("backup_retention_days")
    if isinstance(retention, int) and retention < 7:
        return _finding(
            "RDS_BACKUP_RETENTION_TOO_SHORT", "RDS backup retention is shorter than seven days",
            "medium", asset,
            why=f"Automated backups are retained for {retention} day(s), limiting recovery from delayed incidents.",
            remediation="Set BackupRetentionPeriod to at least seven days or the organization's approved recovery window.",
        )
    return None


def rule_rds_deletion_protection_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.rds.db_instance":
        return None
    if asset.properties.get("deletion_protection") is False:
        return _finding(
            "RDS_DELETION_PROTECTION_DISABLED", "RDS deletion protection is disabled",
            "low", asset,
            why="The database can be deleted without first removing an explicit deletion-protection control.",
            remediation="Enable deletion protection for persistent or production database instances.",
        )
    return None


def rule_rds_proxy_tls_not_required(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.rds.db_proxy":
        return None
    if asset.properties.get("require_tls") is False:
        return _finding(
            "RDS_PROXY_TLS_NOT_REQUIRED", "RDS Proxy does not require TLS",
            "high", asset,
            why="Clients can connect to the database proxy without transport encryption.",
            remediation="Modify the RDS Proxy and enable RequireTLS.",
        )
    return None


def rule_secret_rotation_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.secretsmanager.secret":
        return None
    if asset.properties.get("rotation_enabled") is False:
        return _finding(
            "SECRET_ROTATION_DISABLED", "Secrets Manager automatic rotation is disabled",
            "low", asset,
            why="The secret has no automatic rotation schedule, leaving credential age dependent on manual operations.",
            remediation="Configure an approved rotation Lambda and enable automatic rotation where the credential supports it.",
        )
    return None


def rule_secret_public_policy(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.secretsmanager.secret":
        return None
    if not _facet_known(asset, "resource_policy"):
        return None
    if asset.properties.get("public_policy") is True:
        return _finding(
            "SECRET_PUBLIC_POLICY", "Secret has an unconditional public resource policy",
            "high", asset,
            why="An Allow statement grants an unconditional wildcard AWS principal access to the secret.",
            remediation="Replace the wildcard principal with explicit trusted role ARNs and appropriate conditions.",
        )
    return None


def rule_ecs_container_insights_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ecs.cluster":
        return None
    if asset.properties.get("container_insights") == "disabled":
        return _finding(
            "ECS_CONTAINER_INSIGHTS_DISABLED", "ECS Container Insights is disabled",
            "low", asset,
            why="The cluster lacks enhanced workload metrics and diagnostics used for incident investigation.",
            remediation="Enable the ECS containerInsights cluster setting.",
        )
    return None


def rule_ecs_task_definition_privileged_container(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ecs.task_definition":
        return None
    containers = asset.properties.get("privileged_containers") or []
    if containers:
        return _finding(
            "ECS_TASK_DEFINITION_PRIVILEGED_CONTAINER",
            "ECS task definition enables privileged containers",
            "high", asset,
            why=("Privileged mode weakens container isolation for "
                 f"{', '.join(str(name) for name in containers)}."),
            remediation="Remove privileged mode and grant only the Linux capabilities the workload requires.",
        )
    return None


def rule_ecs_task_definition_host_network(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ecs.task_definition":
        return None
    if asset.properties.get("host_network") is True:
        return _finding(
            "ECS_TASK_DEFINITION_HOST_NETWORK",
            "ECS task definition uses host network mode",
            "high", asset,
            why="Host networking removes network namespace isolation between the task and its container instance.",
            remediation="Use awsvpc networking where supported, or document and isolate the exceptional host-network workload.",
        )
    return None


def rule_eks_public_endpoint_unrestricted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.eks.cluster":
        return None
    cidrs = {str(cidr) for cidr in asset.properties.get("public_access_cidrs") or []}
    if asset.properties.get("endpoint_public_access") is True and "0.0.0.0/0" in cidrs:
        return _finding(
            "EKS_PUBLIC_ENDPOINT_UNRESTRICTED",
            "EKS API endpoint is publicly reachable from all IPv4 addresses",
            "high", asset,
            why="The Kubernetes control-plane endpoint allows access from 0.0.0.0/0.",
            remediation="Disable public endpoint access, or restrict publicAccessCidrs to approved administration networks.",
        )
    return None


def rule_eks_secrets_encryption_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.eks.cluster":
        return None
    if asset.properties.get("secrets_encryption_enabled") is False:
        return _finding(
            "EKS_SECRETS_ENCRYPTION_DISABLED",
            "EKS Kubernetes secrets lack a customer-managed encryption configuration",
            "medium", asset,
            why="No EKS envelope-encryption configuration for Kubernetes secrets was returned by the cluster API.",
            remediation="Associate an approved KMS key through the EKS encryptionConfig for Kubernetes secrets.",
        )
    return None


def rule_ecr_image_scanning_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ecr.repository":
        return None
    if asset.properties.get("image_scan_on_push") is False:
        return _finding(
            "ECR_IMAGE_SCANNING_DISABLED",
            "ECR image scanning on push is disabled",
            "medium", asset,
            why="New images can be deployed without an ECR vulnerability scan being triggered at push time.",
            remediation="Enable scanOnPush and correlate image findings with the runtime workload in Odineyes.",
        )
    return None


def rule_ecr_unrestricted_repository_policy(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ecr.repository" or not _facet_known(asset, "resource_policy"):
        return None
    if asset.properties.get("unrestricted_repository_policy") is True:
        return _finding(
            "ECR_UNRESTRICTED_REPOSITORY_POLICY",
            "ECR repository policy allows any AWS principal",
            "medium", asset,
            why=("An Allow statement grants an unconditional wildcard AWS principal access. "
                 "Private ECR still requires an IAM-authorized authorization token, so this is broad "
                 "cross-account trust rather than anonymous internet exposure."),
            remediation="Replace wildcard principals with explicit trusted identities and scope actions to the required pull or push operations.",
        )
    return None


def rule_ecr_lifecycle_policy_missing(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ecr.repository" or not _facet_known(asset, "lifecycle_policy"):
        return None
    if asset.properties.get("lifecycle_policy_present") is False:
        return _finding(
            "ECR_LIFECYCLE_POLICY_MISSING",
            "ECR repository has no lifecycle policy",
            "low", asset,
            why="Untended image revisions can accumulate, increasing storage cost and the number of stale artifacts retained.",
            remediation="Create a lifecycle policy that retains the image versions needed for operations and removes obsolete revisions.",
        )
    return None


def rule_public_warehouse(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.redshift.cluster":
        return None
    if asset.is_public:
        unencrypted = asset.encryption_enabled is False
        return _finding(
            "PUBLIC_WAREHOUSE", "Internet-facing Redshift cluster",
            "critical" if unencrypted else "high", asset,
            why=("Cluster is publicly accessible"
                 + (" and unencrypted at rest" if unencrypted else "")
                 + " — the warehouse surface is reachable from the internet."),
            remediation="Disable PubliclyAccessible and front access through a VPC endpoint.",
        )
    return None


def rule_cloudtrail_not_logging(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.cloudtrail.trail" or not _facet_known(asset, "logging"):
        return None
    if asset.properties.get("is_logging") is False:
        return _finding(
            "CLOUDTRAIL_NOT_LOGGING", "CloudTrail trail is not actively logging",
            "high", asset,
            why="The trail exists but AWS reports that it is not currently delivering management activity logs.",
            remediation="Start logging on the trail and investigate why delivery stopped.",
        )
    return None


def rule_cloudtrail_no_log_validation(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.cloudtrail.trail":
        return None
    if not asset.properties.get("log_file_validation"):
        return _finding(
            "CLOUDTRAIL_NO_LOG_VALIDATION", "CloudTrail log file validation is disabled",
            "medium", asset,
            why="Without log file validation, tampering with delivered CloudTrail logs can't be detected.",
            remediation="Enable log file validation on the trail.",
        )
    return None


def rule_cloudtrail_no_cloudwatch(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.cloudtrail.trail":
        return None
    if not asset.properties.get("cloudwatch_logs_arn"):
        return _finding(
            "CLOUDTRAIL_NO_CLOUDWATCH", "CloudTrail trail is not wired to CloudWatch Logs",
            "medium", asset,
            why="Without a CloudWatch Logs destination, trail events can't drive real-time metric filters or alarms.",
            remediation="Configure the trail to deliver to a CloudWatch Logs log group.",
        )
    return None


def rule_cloudtrail_not_encrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.cloudtrail.trail":
        return None
    if not asset.properties.get("kms_encrypted"):
        return _finding(
            "CLOUDTRAIL_NOT_ENCRYPTED", "CloudTrail trail logs are not KMS-encrypted",
            "high", asset,
            why="Trail has no KMS key configured — delivered log files rely on default SSE-S3 only.",
            remediation="Configure the trail with a KMS key for log file encryption.",
        )
    return None


def rule_config_not_enabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.config.recorder":
        return None
    if not _facet_known(asset, "recording_status"):
        return None
    if not asset.properties.get("is_recording"):
        return _finding(
            "CONFIG_NOT_ENABLED", "AWS Config recorder exists but is not recording",
            "high", asset,
            why="A Config recorder is defined but stopped — configuration changes are not being tracked.",
            remediation="Start the configuration recorder.",
        )
    return None


def rule_kms_key_pending_deletion(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.kms.key":
        return None
    if asset.properties.get("key_state") == "PendingDeletion":
        return _finding(
            "KMS_KEY_PENDING_DELETION", "KMS key is pending deletion", "high", asset,
            why="Deleting the key can make dependent encrypted data permanently unrecoverable.",
            remediation="Cancel key deletion unless an approved dependency review confirms the key is unused.",
        )
    return None


def rule_kms_key_rotation_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.kms.key":
        return None
    p = asset.properties
    if (p.get("key_manager") == "CUSTOMER" and p.get("key_state") == "Enabled"
            and p.get("rotation_checked") and not p.get("rotation_enabled")):
        return _finding(
            "KMS_KEY_ROTATION_DISABLED", "Customer-managed KMS key has automatic rotation disabled",
            "medium", asset,
            why="Annual key rotation is off — the same key material stays in use indefinitely, widening blast radius if it's ever compromised.",
            remediation="Enable automatic key rotation on the key.",
        )
    return None


def rule_log_group_no_retention(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.cloudwatch.log_group":
        return None
    if asset.properties.get("retention_days") is None:
        return _finding(
            "LOG_GROUP_NO_RETENTION", "CloudWatch log group has no retention policy (logs never expire)",
            "low", asset,
            why="Logs accumulate indefinitely — unbounded storage cost and a compliance gap where a retention window is mandated.",
            remediation="Set a retention period on the log group.",
        )
    return None


def rule_log_group_not_encrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.cloudwatch.log_group":
        return None
    if not asset.properties.get("kms_key_id"):
        return _finding(
            "LOG_GROUP_NOT_ENCRYPTED", "CloudWatch log group is not KMS-encrypted",
            "medium", asset,
            why="Log group uses the default CloudWatch Logs encryption rather than a customer-managed KMS key.",
            remediation="Associate a KMS key with the log group.",
        )
    return None


def rule_ebs_volume_unencrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.volume":
        return None
    if asset.encryption_enabled is False:
        return _finding(
            "EBS_VOLUME_UNENCRYPTED", "EBS volume is not encrypted at rest", "medium", asset,
            why=("Volume data and every snapshot taken from it are stored unencrypted — "
                 "a detached or copied volume exposes its contents directly."),
            remediation="Snapshot the volume, copy the snapshot with encryption enabled, and replace the volume.",
        )
    return None


def rule_ebs_snapshot_public(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.snapshot":
        return None
    if not _facet_known(asset, "share_permissions"):
        return None
    if asset.is_public:
        return _finding(
            "EBS_SNAPSHOT_PUBLIC", "EBS snapshot is shared with all AWS accounts", "critical", asset,
            why=("createVolumePermission includes the 'all' group — any AWS account can copy "
                 "this snapshot and read every byte of the source volume, including credentials "
                 "and application data."),
            remediation="Remove the 'all' group from the snapshot's createVolumePermission attribute.",
        )
    return None


def rule_ebs_snapshot_unencrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.snapshot":
        return None
    if asset.encryption_enabled is False:
        return _finding(
            "EBS_SNAPSHOT_UNENCRYPTED", "EBS snapshot is not encrypted", "medium", asset,
            why="Snapshot data is stored unencrypted, so any copy of it is readable without a key.",
            remediation="Copy the snapshot with encryption enabled and delete the unencrypted original.",
        )
    return None


def rule_vpc_flow_logs_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.ec2.vpc":
        return None
    if not _facet_known(asset, "flow_logs"):
        return None
    if not asset.properties.get("flow_logs_enabled"):
        return _finding(
            "VPC_FLOW_LOGS_DISABLED", "VPC has no active flow log", "medium", asset,
            why=("No ACTIVE flow log covers this VPC — network traffic to and from every "
                 "resource in it is unrecorded, so an intrusion leaves no network evidence."),
            remediation="Create a VPC flow log delivering to CloudWatch Logs or S3.",
        )
    return None


def rule_efs_unencrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.efs.file_system":
        return None
    if asset.encryption_enabled is False:
        return _finding(
            "EFS_UNENCRYPTED", "EFS file system is not encrypted at rest", "high", asset,
            why="Shared file system data is stored unencrypted; encryption at rest cannot be added after creation.",
            remediation="Create an encrypted file system and migrate the data (encryption cannot be enabled in place).",
        )
    return None


def rule_efs_public_policy(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.efs.file_system":
        return None
    if not _facet_known(asset, "resource_policy"):
        return None
    if asset.properties.get("public_policy"):
        return _finding(
            "EFS_PUBLIC_POLICY", "EFS file system policy allows any principal", "critical", asset,
            why=("The file system policy grants access to a wildcard principal with no "
                 "restricting condition — any AWS identity that reaches the mount target can read it."),
            remediation="Scope the EFS file system policy to specific principals or add a restricting condition.",
        )
    return None


def rule_sns_topic_public_policy(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.sns.topic":
        return None
    if not _facet_known(asset, "resource_policy"):
        return None
    if asset.properties.get("public_policy"):
        return _finding(
            "SNS_TOPIC_PUBLIC_POLICY", "SNS topic policy allows any principal", "high", asset,
            why=("The topic policy grants a wildcard principal unconditionally — anyone can "
                 "subscribe to the messages it carries or publish spoofed events into it."),
            remediation="Restrict the topic policy to specific principals or add a condition (e.g. aws:SourceArn).",
        )
    return None


def rule_sns_topic_not_encrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.sns.topic":
        return None
    if not _facet_known(asset, "attributes"):
        return None
    if not asset.properties.get("kms_master_key_id"):
        return _finding(
            "SNS_TOPIC_NOT_ENCRYPTED", "SNS topic has no server-side encryption", "medium", asset,
            why="Messages held by the topic are stored without a KMS key.",
            remediation="Set a KMS master key on the topic to enable server-side encryption.",
        )
    return None


def rule_sqs_queue_public_policy(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.sqs.queue":
        return None
    if not _facet_known(asset, "resource_policy"):
        return None
    if asset.properties.get("public_policy"):
        return _finding(
            "SQS_QUEUE_PUBLIC_POLICY", "SQS queue policy allows any principal", "high", asset,
            why=("The queue policy grants a wildcard principal unconditionally — anyone can read "
                 "queued messages or inject work into the consuming system."),
            remediation="Restrict the queue policy to specific principals or add a condition (e.g. aws:SourceArn).",
        )
    return None


def rule_sqs_queue_not_encrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.sqs.queue":
        return None
    if not _facet_known(asset, "attributes"):
        return None
    # SQS-managed SSE counts as encryption at rest; only a queue with neither
    # that nor a KMS key is genuinely unencrypted.
    if not asset.encryption_enabled:
        return _finding(
            "SQS_QUEUE_NOT_ENCRYPTED", "SQS queue has no server-side encryption", "medium", asset,
            why="Queue has neither a KMS key nor SQS-managed SSE, so message bodies rest unencrypted.",
            remediation="Enable SQS-managed SSE or attach a KMS key to the queue.",
        )
    return None


def rule_dynamodb_pitr_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.dynamodb.table":
        return None
    if not _facet_known(asset, "point_in_time_recovery"):
        return None
    if asset.properties.get("point_in_time_recovery_status") != "ENABLED":
        return _finding(
            "DYNAMODB_PITR_DISABLED", "DynamoDB table has point-in-time recovery disabled",
            "medium", asset,
            why=("Without PITR the table cannot be restored to a moment before an accidental "
                 "or malicious write, so a destructive change is unrecoverable."),
            remediation="Enable point-in-time recovery on the table.",
        )
    return None


def rule_dynamodb_deletion_protection_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.dynamodb.table":
        return None
    if not asset.properties.get("deletion_protection_enabled"):
        return _finding(
            "DYNAMODB_DELETION_PROTECTION_DISABLED",
            "DynamoDB table has deletion protection disabled", "low", asset,
            why="A single API call or misapplied IaC change can delete the table and its data.",
            remediation="Enable deletion protection on the table.",
        )
    return None


def rule_dynamodb_not_cmk_encrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.dynamodb.table":
        return None
    # DynamoDB is always encrypted at rest; the control is *which* key. Absent
    # SSEDescription means the AWS-owned key, which offers no key policy, no
    # audit trail and no revocation.
    if not asset.properties.get("kms_key_arn"):
        return _finding(
            "DYNAMODB_NOT_CMK_ENCRYPTED",
            "DynamoDB table uses the AWS-owned key rather than a KMS key", "low", asset,
            why=("The AWS-owned default key has no key policy, no CloudTrail record of use and "
                 "cannot be revoked, so key access cannot be governed or audited."),
            remediation="Switch the table to a customer-managed or AWS-managed KMS key.",
        )
    return None


def rule_apigateway_stage_logging_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.apigateway.rest_api":
        return None
    if not _facet_known(asset, "stages"):
        return None
    unlogged = [s["name"] for s in asset.properties.get("stages") or []
                if not s.get("access_logging_enabled") and s.get("name")]
    if unlogged:
        return _finding(
            "APIGATEWAY_STAGE_LOGGING_DISABLED",
            "API Gateway stage has access logging disabled", "medium", asset,
            why=(f"Stage(s) {', '.join(sorted(unlogged))} have no access log destination — "
                 "requests to the API leave no record for investigation."),
            remediation="Configure an access log destination on each deployed stage.",
        )
    return None


def rule_apigateway_stage_cache_unencrypted(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.apigateway.rest_api":
        return None
    if not _facet_known(asset, "stages"):
        return None
    exposed = [s["name"] for s in asset.properties.get("stages") or []
               if s.get("cache_enabled") and not s.get("cache_data_encrypted") and s.get("name")]
    if exposed:
        return _finding(
            "APIGATEWAY_STAGE_CACHE_UNENCRYPTED",
            "API Gateway stage caches responses without encryption", "medium", asset,
            why=(f"Stage(s) {', '.join(sorted(exposed))} cache responses with cacheDataEncrypted "
                 "off — cached response bodies are stored in the clear."),
            remediation="Enable cache data encryption on the stage's method settings.",
        )
    return None


def rule_guardduty_detector_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.guardduty.detector":
        return None
    if asset.properties.get("status") != "ENABLED":
        return _finding(
            "GUARDDUTY_DETECTOR_DISABLED", "GuardDuty detector exists but is suspended",
            "high", asset,
            why=("The detector is present but not ENABLED, so threat detection is off in this "
                 "region while the configuration still suggests it is covered."),
            remediation="Enable the GuardDuty detector in this region.",
        )
    return None


def rule_root_account_access_key(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.iam.account_settings":
        return None
    if not _facet_known(asset, "account_summary"):
        return None
    if asset.properties.get("root_access_keys_present"):
        return _finding(
            "ROOT_ACCOUNT_ACCESS_KEY", "Root user has active access keys", "critical", asset,
            why=("The root user holds long-lived programmatic credentials. They cannot be "
                 "scoped, are exempt from every SCP and IAM boundary, and their leak means "
                 "unrecoverable, total account compromise."),
            remediation="Delete the root access keys and use IAM roles for programmatic access.",
        )
    return None


def rule_root_account_mfa_disabled(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.iam.account_settings":
        return None
    if not _facet_known(asset, "account_summary"):
        return None
    if not asset.properties.get("root_mfa_enabled"):
        return _finding(
            "ROOT_ACCOUNT_MFA_DISABLED", "Root user does not have MFA enabled", "critical", asset,
            why=("The account's most privileged identity is protected by a password alone — a "
                 "credential-stuffing or phishing hit takes the whole account."),
            remediation="Enable a hardware or virtual MFA device on the root user.",
        )
    return None


def rule_iam_password_policy_weak(asset: AssetLike) -> Finding | None:
    if asset.asset_type != "aws.iam.account_settings":
        return None
    if not _facet_known(asset, "password_policy"):
        return None
    p = asset.properties
    if not p.get("password_policy_present"):
        return _finding(
            "IAM_PASSWORD_POLICY_MISSING", "Account has no IAM password policy", "medium", asset,
            why="Console users can set passwords of any length or complexity.",
            remediation="Set an account password policy (minimum length 14, reuse prevention 24).",
        )
    # CIS AWS Foundations: length >= 14 and the last 24 passwords blocked.
    weaknesses = []
    if (p.get("password_min_length") or 0) < 14:
        weaknesses.append(f"minimum length {p.get('password_min_length')} (< 14)")
    if (p.get("password_reuse_prevention") or 0) < 24:
        weaknesses.append(f"reuse prevention {p.get('password_reuse_prevention') or 0} (< 24)")
    if weaknesses:
        return _finding(
            "IAM_PASSWORD_POLICY_WEAK", "IAM password policy is weaker than the CIS baseline",
            "medium", asset,
            why=f"Password policy has {'; '.join(weaknesses)}.",
            remediation="Raise the minimum password length to 14 and password reuse prevention to 24.",
        )
    return None


SINGLE_ASSET_RULES: list[Callable[[AssetLike], Finding | None]] = [
    rule_public_admin_role,
    rule_identity_unrestricted_admin_grant,
    rule_identity_privilege_escalation_grant,
    rule_iam_user_direct_policy_attachment,
    rule_iam_user_privileged_longlived_key,
    rule_iam_user_console_no_mfa,
    rule_dormant_privileged_identity,
    rule_overly_permissive_cidr,
    rule_public_unencrypted_db,
    rule_public_database,
    rule_unencrypted_database,
    rule_public_bucket,
    rule_s3_default_encryption_disabled,
    rule_s3_versioning_disabled,
    rule_s3_access_logging_disabled,
    rule_s3_public_access_block_incomplete,
    rule_public_compute,
    rule_ec2_imdsv2_not_required,
    rule_subnet_auto_assign_public_ip_enabled,
    rule_public_lambda,
    rule_db_cluster_unencrypted,
    rule_db_cluster_deletion_protection_disabled,
    rule_rds_backup_retention_too_short,
    rule_rds_deletion_protection_disabled,
    rule_rds_proxy_tls_not_required,
    rule_secret_rotation_disabled,
    rule_secret_public_policy,
    rule_ecs_container_insights_disabled,
    rule_ecs_task_definition_privileged_container,
    rule_ecs_task_definition_host_network,
    rule_eks_public_endpoint_unrestricted,
    rule_eks_secrets_encryption_disabled,
    rule_ecr_image_scanning_disabled,
    rule_ecr_unrestricted_repository_policy,
    rule_ecr_lifecycle_policy_missing,
    rule_public_warehouse,
    rule_cloudtrail_not_logging,
    rule_cloudtrail_no_log_validation,
    rule_cloudtrail_no_cloudwatch,
    rule_cloudtrail_not_encrypted,
    rule_config_not_enabled,
    rule_kms_key_pending_deletion,
    rule_kms_key_rotation_disabled,
    rule_log_group_no_retention,
    rule_log_group_not_encrypted,
    rule_ebs_volume_unencrypted,
    rule_ebs_snapshot_public,
    rule_ebs_snapshot_unencrypted,
    rule_vpc_flow_logs_disabled,
    rule_efs_unencrypted,
    rule_efs_public_policy,
    rule_sns_topic_public_policy,
    rule_sns_topic_not_encrypted,
    rule_sqs_queue_public_policy,
    rule_sqs_queue_not_encrypted,
    rule_dynamodb_pitr_disabled,
    rule_dynamodb_deletion_protection_disabled,
    rule_dynamodb_not_cmk_encrypted,
    rule_apigateway_stage_logging_disabled,
    rule_apigateway_stage_cache_unencrypted,
    rule_guardduty_detector_disabled,
    rule_root_account_access_key,
    rule_root_account_mfa_disabled,
    rule_iam_password_policy_weak,
]


# ── combination (toxic-path) rules ─────────────────────────────

def rule_public_compute_to_admin(assets: list[AssetLike]) -> list[Finding]:
    """Public EC2 with an instance profile + an admin role present in the same set.

    Wiz-style toxic combination: an internet-reachable host that can act with
    admin credentials. Instance-profile -> role binding is not carried in the raw
    EC2 record, so this links at account scope and names the admin role(s).
    """
    admin_roles = [a for a in assets
                   if a.asset_type == "aws.iam.role" and a.properties.get("has_admin")]
    if not admin_roles:
        return []
    role_ids = [a.resource_id for a in admin_roles]

    findings: list[Finding] = []
    for a in assets:
        if a.asset_type != "aws.ec2.instance" or not a.is_public:
            continue
        if not a.properties.get("iam_instance_profile"):
            continue
        findings.append(_finding(
            "PUBLIC_COMPUTE_TO_ADMIN",
            "Public compute can reach admin credentials", "critical", a,
            why=("Internet-facing instance has an instance profile attached while admin "
                 "role(s) exist in the account — a path from public host to account takeover."),
            remediation="Attach a least-privilege role to the instance; remove unused admin roles.",
            related=role_ids,
        ))
    return findings


def _sg_attachments(assets: list[AssetLike]) -> dict[str, list[AssetLike]]:
    """security-group id -> the assets that actually use it.

    A security group is a rule set, not a location. What it costs you depends
    entirely on what sits behind the port, so every severity decision about an
    open ingress rule needs this map first.
    """
    attachments: dict[str, list[AssetLike]] = {}
    for asset in assets:
        if asset.asset_type == "aws.ec2.security_group":
            continue
        ids = {str(sid) for sid in asset.properties.get("security_group_ids") or []}
        ids.update(
            str(rel.get("target_id"))
            for rel in asset.relationships or []
            if rel.get("type") == "USES_SECURITY_GROUP" and rel.get("target_id")
        )
        for sg_id in ids:
            attachments.setdefault(sg_id, []).append(asset)
    return attachments


def rule_world_open_sensitive_port(assets: list[AssetLike]) -> list[Finding]:
    """World-open sensitive ingress, graded by proven workload reachability.

    The security group is a rule set, not an endpoint. Critical is deliberately
    impossible here: critical requires a separate toxic-path rule with
    exploitability, privilege or sensitive-data evidence.

    This is the node-vs-path distinction in practice. Asking only "does this
    group allow 0.0.0.0/0" reports every private RDS instance whose group was
    written loosely, which is the loudest false positive a CSPM produces. The
    question that matters is whether a packet can traverse
    internet -> IGW -> subnet -> workload -> this group, so every attached
    workload is put through the proven-path evaluator, not just EC2. When the
    path is broken for all of them the finding is marked ``suppressed_by=path``
    rather than emitted: the loose rule is still recorded, it just is not an
    alert while nothing behind it is reachable.
    """
    attachments = _sg_attachments(assets)
    topology = build_network_topology(assets)
    findings: list[Finding] = []

    for sg in assets:
        if sg.asset_type != "aws.ec2.security_group":
            continue
        hits = [p for p in sg.properties.get("open_ports") or [] if p in SENSITIVE_PORTS]
        if not hits:
            continue
        labels = ", ".join(SENSITIVE_PORTS[p] for p in hits)

        attached = attachments.get(sg.resource_id.rsplit("/", 1)[-1], [])
        reachable: list[AssetLike] = []
        unverified: list[tuple[AssetLike, list[str]]] = []
        blocked: list[tuple[AssetLike, list[str]]] = []
        for workload in attached:
            assessments = [
                assess_network_layer(
                    workload, topology=topology, port=22 if port == 0 else port
                )
                for port in hits
            ]
            # not_applicable is the RDS evaluator saying PubliclyAccessible is
            # false — an observed fact that breaks the path, not a gap in it.
            if all(result.status == "not_applicable" for result in assessments):
                blocked.append((workload, ["the resource has no public endpoint configured"]))
            elif any(result.status == "reachable" for result in assessments):
                reachable.append(workload)
            elif any(result.status == "unverified" for result in assessments):
                unverified.append((
                    workload,
                    sorted({item for result in assessments for item in result.missing}),
                ))
            else:
                blocked.append((
                    workload,
                    sorted({item for result in assessments for item in result.blockers}),
                ))

        if not attached:
            severity = "low"
            title = f"Security group allows unrestricted {labels} ingress"
            why = (f"The group permits 0.0.0.0/0 or ::/0 to {labels}, but no collected "
                   "resource uses it. No live endpoint is proven exposed today.")
            remediation = "Delete the security group, or narrow the rule before it is attached to a workload."
        elif reachable:
            severity = "high"
            names = ", ".join(sorted(_short_name(a.resource_id) for a in reachable)[:5])
            title = f"Internet can reach {labels} on attached EC2 instance"
            why = (f"A complete Internet path to {labels} is proven for {names}: the "
                   "instance has a public IPv4 address, its security group allows the "
                   "world, its subnet routes through an attached Internet gateway, and "
                   "its network ACL permits request and response traffic. Intentional "
                   "remote access does not make unrestricted source access safe.")
            remediation = ("Keep remote access, but restrict the source to trusted office/VPN CIDRs, "
                           "use a bastion, or use AWS Systems Manager Session Manager.")
        else:
            severity = "medium"
            title = f"Security group allows unrestricted {labels} ingress"
            names = ", ".join(sorted(_short_name(a.resource_id) for a in attached)[:5])
            details: list[str] = []
            missing = sorted({item for _, values in unverified for item in values})
            blockers = sorted({item for _, values in blocked for item in values})
            if missing:
                details.append("reachability is unverified because collection lacks " + ", ".join(missing))
            if blockers:
                details.append("observed path blockers: " + "; ".join(blockers))
            reason = "; ".join(details) or "no attached EC2 instance has a public endpoint"
            why = (f"The group permits 0.0.0.0/0 or ::/0 to {labels} and is attached to "
                   f"{len(attached)} resource(s) ({names}), but Odineyes did not prove a "
                   f"complete Internet path: {reason}. This is a control gap, not a "
                   "confirmed public endpoint.")
            remediation = ("Narrow the ingress to the CIDR or security group that actually needs it, "
                           "so a future public IP does not silently open this port.")

        finding = _finding(
            "WORLD_OPEN_SENSITIVE_PORT",
            title,
            severity, sg, why=why, remediation=remediation,
            related=[a.resource_id for a in (reachable or attached)],
        )
        if attached and not reachable and not unverified:
            # Every attached workload was *proven* unreachable — a private
            # database, an instance with no public IP, a subnet with no
            # gateway route. The graph path breaks, so this is not an alert.
            names = ", ".join(sorted(_short_name(a.resource_id) for a, _ in blocked)[:5])
            finding.suppressed_by = "path"
            finding.suppressed_why = (
                f"no internet path exists to any of the {len(attached)} attached "
                f"resource(s) ({names}): "
                + "; ".join(sorted({item for _, values in blocked for item in values})[:3])
            )
        findings.append(finding)
    return findings


def rule_unused_security_group(assets: list[AssetLike]) -> list[Finding]:
    """A security group referenced by no instance, database, or ENI in the
    inventory. Account-scope because "used" is defined by *other* assets — a
    single SG can't know its own attachments. Cleanup/hygiene, so severity low.

    ponytail: an SG referenced only by a resource type we don't collect yet
    (e.g. an elasticache node) would be a false 'unused'. As the collector's
    service coverage grows this narrows on its own — the referenced set is built
    from whatever assets are present, no per-service code here."""
    referenced: set[str] = set()
    sgs: list[AssetLike] = []
    for a in assets:
        if a.asset_type == "aws.ec2.security_group":
            sgs.append(a)
            continue
        for sid in a.properties.get("security_group_ids") or []:
            referenced.add(str(sid))
        for rel in a.relationships or []:
            if rel.get("type") == "USES_SECURITY_GROUP":
                referenced.add(str(rel.get("target_id")))

    findings: list[Finding] = []
    for sg in sgs:
        short = sg.resource_id.rsplit("/", 1)[-1]
        if short in referenced:
            continue
        # An exposed SG is covered by its own exposure finding — don't also
        # report it as harmless 'unused' cleanup.
        if sg.properties.get("open_ports") or sg.properties.get("wide_open_cidrs"):
            continue
        findings.append(_finding(
            "UNUSED_SECURITY_GROUP", "Unused security group (attached to nothing)", "low", sg,
            why=("No instance, database, or ENI in the inventory references this security "
                 "group. Unused SGs accumulate stale rules and widen the audit surface."),
            remediation="Delete the security group after confirming nothing outside the inventory uses it.",
        ))
    return findings


def rule_cloudtrail_no_multiregion(assets: list[AssetLike]) -> list[Finding]:
    """CIS 3.1: at least one trail must be multi-region AND actively logging.
    Account-scope, not single-asset — firing per-trail would false-positive an
    account that has one good multi-region trail plus extra single-region ones.
    A zero-trail account is a coverage gap (see inventory/coverage.py), not a
    finding: there's no asset to attach a Finding to."""
    trails = [a for a in assets if a.asset_type == "aws.cloudtrail.trail"]
    if not trails:
        return []
    if any(t.properties.get("is_multi_region") and t.properties.get("is_logging") for t in trails):
        return []
    # A multi-region trail whose status call was denied may still be actively
    # logging. Do not convert that evidence gap into a failed control.
    if any(
        t.properties.get("is_multi_region")
        and not _facet_known(t, "logging")
        for t in trails
    ):
        return []
    target = trails[0]
    return [_finding(
        "CLOUDTRAIL_NOT_MULTIREGION", "No multi-region CloudTrail trail is actively logging",
        "high", target,
        why=(f"CIS 3.1 requires at least one trail covering all regions and actively logging. "
             f"{len(trails)} trail(s) exist in the account but none are both multi-region and logging."),
        remediation="Enable a multi-region trail with logging turned on.",
        related=[t.resource_id for t in trails[1:]],
    )]


def rule_cloudtrail_s3_public(assets: list[AssetLike]) -> list[Finding]:
    """CIS 3.3: the S3 bucket a trail delivers to must not be publicly
    accessible — otherwise the audit trail itself can be read or tampered with."""
    buckets_by_name = {
        a.resource_id.rsplit(":::", 1)[-1]: a
        for a in assets if a.asset_type == "aws.s3.bucket"
    }
    findings: list[Finding] = []
    for t in assets:
        if t.asset_type != "aws.cloudtrail.trail":
            continue
        bucket_name = t.properties.get("s3_bucket_name")
        bucket = buckets_by_name.get(bucket_name) if bucket_name else None
        if bucket is not None and bucket.is_public:
            findings.append(_finding(
                "CLOUDTRAIL_S3_PUBLIC", "CloudTrail log bucket is publicly accessible",
                "critical", t,
                why=(f"Trail delivers to S3 bucket '{bucket_name}', which is publicly accessible — "
                     "audit logs can be read or tampered with by anyone."),
                remediation="Remove public access from the CloudTrail log bucket.",
                related=[bucket.resource_id],
            ))
    return findings


def rule_guardduty_not_enabled(assets: list[AssetLike]) -> list[Finding]:
    """A region with GuardDuty switched off returns no detector at all, so this
    cannot be a single-asset rule. It attaches to the account settings
    pseudo-asset — the only asset that exists whether or not anything is
    configured. Absent that asset (IAM summary denied), stay silent rather than
    convert missing evidence into a failed control."""
    account = next((a for a in assets if a.asset_type == "aws.iam.account_settings"), None)
    if account is None:
        return []
    detectors = [a for a in assets if a.asset_type == "aws.guardduty.detector"]
    if any(d.properties.get("status") == "ENABLED" for d in detectors):
        return []
    if detectors:
        # Every detector is suspended — already reported per-detector.
        return []
    return [_finding(
        "GUARDDUTY_NOT_ENABLED", "GuardDuty is not enabled in any scanned region",
        "high", account,
        why=("No GuardDuty detector was found in any region covered by this scan. Account "
             "compromise, crypto-mining and credential-exfiltration signals go undetected."),
        remediation="Enable GuardDuty in every region in use, ideally via an Organizations delegated administrator.",
    )]


COMBINATION_RULES: list[Callable[[list[AssetLike]], list[Finding]]] = [
    rule_world_open_sensitive_port,
    rule_public_compute_to_admin,
    rule_unused_security_group,
    rule_cloudtrail_no_multiregion,
    rule_cloudtrail_s3_public,
    rule_guardduty_not_enabled,
]


# ── engine ─────────────────────────────────────────────────────

def evaluate(
    assets: Iterable[AssetLike],
    *,
    dspm_taxonomies: dict[str, Any] | None = None,
    include_suppressed: bool = False,
) -> list[Finding]:
    """Run every rule over the asset set; return findings sorted by severity.

    Detections then pass through ``inventory/tuning.py``, which mutes the ones
    that are true but not actionable and can re-grade severity from tag intent
    and data classification. Set ``include_suppressed`` to get the muted ones
    back — they carry ``suppressed_by`` and are what a "why was I not told"
    query reads.
    """
    assets = list(assets)
    findings: list[Finding] = []
    for asset in assets:
        for rule in SINGLE_ASSET_RULES:
            f = rule(asset)
            if f is not None:
                findings.append(f)
    for combo in COMBINATION_RULES:
        findings.extend(combo(assets))
    apply_tuning(findings, assets, dspm_taxonomies=dspm_taxonomies)
    if not include_suppressed:
        findings = [f for f in findings if not f.suppressed_by]
    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.rule_id, f.resource_id))
    return findings


def evaluate_account(session, account_id: int | None = None,
                     **kwargs: Any) -> list[Finding]:
    """Run the engine over active persisted assets (optionally one account)."""
    from sqlalchemy import select

    from odineyes.db.models import Asset

    stmt = select(Asset).where(Asset.is_active.is_(True))
    if account_id is not None:
        stmt = stmt.where(Asset.account_id == account_id)
    if account_id is not None and "dspm_taxonomies" not in kwargs:
        from odineyes.inventory.tuning import dspm_taxonomies_for_account
        kwargs["dspm_taxonomies"] = dspm_taxonomies_for_account(session, account_id)
    return evaluate(session.execute(stmt).scalars().all(), **kwargs)


if __name__ == "__main__":
    # Offline self-check for the remediation command builder — the only piece
    # with non-trivial string logic (ARN tail extraction + template fill).
    assert _short_name("arn:aws:iam::123456789012:role/path/AdminRole") == "AdminRole"
    assert _short_name("sg-0abc123") == "sg-0abc123"
    assert _short_name("my-public-bucket") == "my-public-bucket"
    assert remediation_command("PUBLIC_BUCKET", "my-public-bucket").startswith(
        "aws s3api put-public-access-block --bucket my-public-bucket")
    assert "--role-name AdminRole" in remediation_command(
        "PUBLIC_ADMIN_ROLE", "arn:aws:iam::1:role/AdminRole")
    assert remediation_command("PUBLIC_COMPUTE", "i-123") == ""  # judgement call, no one-liner
    print("rules remediation self-check OK")
