from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass(frozen=True)
class Ec2InstanceRecord:
    instance_id: str
    instance_type: str
    state: str
    private_ip: Optional[str]
    public_ip: Optional[str]
    vpc_id: str
    subnet_id: str
    image_id: str
    tags: dict[str, str]
    is_public: bool

@dataclass(frozen=True)
class SecurityGroupRecord:
    sg_id: str
    is_internet_exposed: bool

@dataclass(frozen=True)
class IamCredentialRecord:
    role_name: str
    has_admin_policy: bool

@dataclass(frozen=True)
class SecretFinding:
    secret_type: str
    file_path: str
    value_hash: str
    entropy_score: float
    line_number: int

@dataclass(frozen=True)
class RdsInstanceRecord:
    db_id: str
    engine: str
    endpoint_address: str
    vpc_id: str
    publicly_accessible: bool
