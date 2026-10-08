"""Stable read models for the inventory resource explorer.

Database rows stay storage-oriented.  These models expose a product-oriented
contract so API consumers do not need to understand normalization internals.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class ResourceIdentity(BaseModel):
    name: str
    resource_id: str
    provider: str
    account_id: int
    account_name: Optional[str] = None
    asset_type: str
    service: str
    category: str
    kind: str


class ResourceScope(BaseModel):
    region: str
    level: Literal["global", "regional"]


class EncryptionPosture(BaseModel):
    status: Literal["enabled", "disabled", "not_applicable"]


class RiskPosture(BaseModel):
    score: float = Field(ge=0, le=100)
    severity: Literal["critical", "high", "medium", "low", "none"]


class FindingPosture(BaseModel):
    total: int = Field(ge=0)
    by_severity: dict[str, int]


class ResourcePosture(BaseModel):
    exposure: Literal["private", "vpc", "public"]
    is_public: bool
    encryption: EncryptionPosture
    risk: RiskPosture
    findings: FindingPosture


class ResourceLifecycle(BaseModel):
    status: Literal["active", "inactive"]
    first_seen_at: Optional[str] = None
    last_scanned_at: Optional[str] = None
    resource_created_at: Optional[str] = None


class ResourceMetadata(BaseModel):
    tags: dict[str, Any]
    relationship_count: int = Field(ge=0)


class InventoryResource(BaseModel):
    id: int
    identity: ResourceIdentity
    scope: ResourceScope
    posture: ResourcePosture
    lifecycle: ResourceLifecycle
    metadata: ResourceMetadata


class FacetValue(BaseModel):
    value: str
    label: str
    count: int = Field(ge=0)


class InventoryFacets(BaseModel):
    categories: list[FacetValue]
    services: list[FacetValue]
    types: list[FacetValue]
    regions: list[FacetValue]
    exposures: list[FacetValue]


class InventoryTotals(BaseModel):
    assets: int = Field(ge=0)
    filtered: int = Field(ge=0)
    public: int = Field(ge=0)
    elevated_risk: int = Field(ge=0)


class Pagination(BaseModel):
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)
    total: int = Field(ge=0)


class InventoryResourcePage(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    items: list[InventoryResource]
    totals: InventoryTotals
    facets: InventoryFacets
    pagination: Pagination
