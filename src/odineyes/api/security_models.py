"""Product-facing read models for findings, identity, and data security."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from odineyes.api.inventory_models import FacetValue, Pagination

Severity = Literal["critical", "high", "medium", "low", "info"]


class FindingVerdict(BaseModel):
    title: str
    rule_id: str
    category: str
    signal: Literal["active_threat", "network_hygiene"]


class FindingResource(BaseModel):
    resource_id: str
    name: str
    asset_type: str
    provider: str
    service: str
    account_id: int
    account_name: Optional[str] = None


class FindingSensitivity(BaseModel):
    label: str
    taxonomies: list[str]


class FindingPostureModel(BaseModel):
    severity: Severity
    status: Literal["open", "suppressed", "resolved"]
    risk_score: float = Field(ge=0, le=100)
    exposure: Literal["public", "vpc", "private", "unknown"]
    elevated: bool
    data_sensitivity: Optional[FindingSensitivity] = None


class FindingEvidence(BaseModel):
    why: str
    compliance: dict[str, list[str]]
    related_resources: list[str]
    suppressed_by: Optional[str] = None
    suppressed_why: Optional[str] = None


class FindingRemediation(BaseModel):
    guidance: str
    cli: Optional[str] = None


class FindingLifecycle(BaseModel):
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    resolved_at: Optional[str] = None


class ModeledFinding(BaseModel):
    id: int
    verdict: FindingVerdict
    resource: FindingResource
    posture: FindingPostureModel
    evidence: FindingEvidence
    remediation: FindingRemediation
    lifecycle: FindingLifecycle


class FindingFacets(BaseModel):
    severities: list[FacetValue]
    statuses: list[FacetValue]
    rules: list[FacetValue]
    categories: list[FacetValue]
    services: list[FacetValue]
    signals: list[FacetValue]


class FindingTotals(BaseModel):
    open: int = Field(ge=0)
    active_threats: int = Field(ge=0)
    network_hygiene: int = Field(ge=0)
    resolved: int = Field(ge=0)
    suppressed: int = Field(ge=0)
    critical: int = Field(ge=0)
    elevated: int = Field(ge=0)
    filtered: int = Field(ge=0)


class ModeledFindingPage(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    items: list[ModeledFinding]
    totals: FindingTotals
    facets: FindingFacets
    pagination: Pagination


class PrincipalIdentity(BaseModel):
    name: str
    resource_id: str
    provider: str
    account_id: int
    account_name: Optional[str] = None
    principal_type: str


class PrincipalPrivilege(BaseModel):
    admin: bool
    admin_grant: bool = False
    boundary_restricts_admin: bool = False
    admin_reason: str
    privilege_escalation_actions: list[str]
    effective_privilege_escalation_actions: list[str] = Field(default_factory=list)


class PrincipalAuthorization(BaseModel):
    scope: str
    effective_access_complete: bool
    unevaluated_policy_layers: list[str]
    policy_sources: int = Field(ge=0)
    direct_policy_sources: int = Field(ge=0)
    inherited_policy_sources: int = Field(ge=0)
    allow_statements: int = Field(ge=0)
    explicit_denies: int = Field(ge=0)
    conditional_statements: int = Field(ge=0)
    wildcard_action_statements: int = Field(ge=0)
    wildcard_resource_statements: int = Field(ge=0)
    groups: list[str]
    permissions_boundary_arn: Optional[str] = None
    permissions_boundary_state: str
    analysis_complete: bool


class PrincipalAuthentication(BaseModel):
    console_enabled: bool
    mfa_enabled: bool
    access_key_active: bool
    access_key_max_age_days: int
    access_key_last_used_days: Optional[int] = None


class PrincipalTrust(BaseModel):
    level: Literal["public", "external", "verified", "account", "none"]
    publicly_assumable: bool
    external: bool
    onboarding_verified: bool = False
    principals: list[str]


class PrincipalPosture(BaseModel):
    risk_score: float = Field(ge=0, le=100)
    severity: Literal["critical", "high", "medium", "low", "none"]
    open_findings: int = Field(ge=0)
    attack_paths: int = Field(ge=0)


class PrincipalLifecycle(BaseModel):
    age_days: Optional[int] = None
    last_used_days: Optional[int] = None
    last_scanned_at: Optional[str] = None


class IdentityPrincipal(BaseModel):
    id: int
    identity: PrincipalIdentity
    privilege: PrincipalPrivilege
    authorization: PrincipalAuthorization
    authentication: PrincipalAuthentication
    trust: PrincipalTrust
    posture: PrincipalPosture
    lifecycle: PrincipalLifecycle
    metadata: dict[str, Any]


class IdentityFacets(BaseModel):
    principal_types: list[FacetValue]
    trust_levels: list[FacetValue]
    severities: list[FacetValue]


class IdentityTotals(BaseModel):
    principals: int = Field(ge=0)
    roles: int = Field(ge=0)
    users: int = Field(ge=0)
    admins: int = Field(ge=0)
    admin_grants: int = Field(ge=0)
    bounded: int = Field(ge=0)
    inherited_access: int = Field(ge=0)
    incomplete_evaluations: int = Field(ge=0)
    mfa_gaps: int = Field(ge=0)
    external_trust: int = Field(ge=0)
    filtered: int = Field(ge=0)


class IdentityPrincipalPage(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    items: list[IdentityPrincipal]
    totals: IdentityTotals
    facets: IdentityFacets
    pagination: Pagination


class DataStoreIdentity(BaseModel):
    name: str
    resource_id: str
    provider: str
    account_id: int
    account_name: Optional[str] = None
    asset_type: str
    service: str
    store_type: str
    region: str


class DataClassification(BaseModel):
    status: Literal["classified", "unclassified"]
    label: str
    data_types: list[str]
    taxonomies: list[str]
    frameworks: list[str]
    sensitivity_score: float = Field(ge=0)
    records_estimated: int = Field(ge=0)
    objects_sampled: int = Field(ge=0)


class DataProtection(BaseModel):
    public: bool
    exposure: Literal["public", "vpc", "private"]
    encryption: Literal["enabled", "disabled", "unknown"]
    posture_findings: list[str]


class DataRisk(BaseModel):
    score: float = Field(ge=0, le=100)
    severity: Literal["critical", "high", "medium", "low", "none"]
    open_findings: int = Field(ge=0)


class DataLifecycle(BaseModel):
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None


class DataStore(BaseModel):
    id: int
    identity: DataStoreIdentity
    classification: DataClassification
    protection: DataProtection
    risk: DataRisk
    lifecycle: DataLifecycle
    metadata: dict[str, Any]


class DataFacets(BaseModel):
    services: list[FacetValue]
    store_types: list[FacetValue]
    labels: list[FacetValue]
    regions: list[FacetValue]
    exposures: list[FacetValue]


class DataTotals(BaseModel):
    stores: int = Field(ge=0)
    classified: int = Field(ge=0)
    public: int = Field(ge=0)
    unencrypted: int = Field(ge=0)
    sensitive: int = Field(ge=0)
    filtered: int = Field(ge=0)


class DataStorePage(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    items: list[DataStore]
    totals: DataTotals
    facets: DataFacets
    pagination: Pagination
