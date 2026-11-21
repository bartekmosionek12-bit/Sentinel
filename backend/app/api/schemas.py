"""Schematy wejścia i wyjścia API (Pydantic v2)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Typy, które można dodać ręcznie albo z CSV.
AssetType = Literal["host", "domain", "ip", "service", "application"]
# Typy w odpowiedziach: także urządzenia z AD, MDM i CMDB (Etap 6, models.inventory.ASSET_TYPES).
AnyAssetType = Literal[
    "host",
    "domain",
    "ip",
    "service",
    "application",
    "workstation",
    "laptop",
    "server",
    "network",
    "printer",
    "iot",
    "cloud",
    "ai_system",
]
Exposure = Literal["internet", "internal"]
AssetStatus = Literal["active", "missing", "retired", "shadow"]


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    database: bool
    redis: bool
    demo_mode: bool


class AssetIn(BaseModel):
    type: AssetType
    name: str = Field(min_length=1, max_length=255)
    exposure: Exposure = "internal"
    criticality: int = Field(default=3, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list)


class AssetOut(OrmModel):
    id: uuid.UUID
    type: AnyAssetType
    name: str
    exposure: Exposure
    criticality: int
    owner: str | None
    tags: list[str]
    status: AssetStatus
    first_seen: datetime
    last_seen: datetime


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class AuditLogOut(OrmModel):
    id: int
    ts: datetime
    actor: str
    actor_type: str | None = None
    actor_id: str | None = None
    on_behalf_of: str | None = None
    request_id: str | None = None
    action: str
    object_type: str | None
    object_id: str | None
    reason: str
    inputs: dict[str, Any]
    hash: str
    prev_hash: str
    hash_version: int = 1


class AuditChainOut(BaseModel):
    ok: bool
    entries: int
    broken_at_id: int | None = None
    detail: str | None = None


class ScopeOut(BaseModel):
    allowed_domains: list[str]
    allowed_cidrs: list[str]
    denied_domains: list[str]
    denied_cidrs: list[str]
    default_rate_per_minute: int
    scan_packets_per_second: int
    scan_workers: int
    demo_mode: bool
    demo_lab_cidr: str
    demo_approval_expires_at: datetime | None


class ScopeCheckIn(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    intrusiveness: Literal[1, 2, 3] = 1


class ScopeCheckOut(BaseModel):
    target: str
    allowed: bool
    decision: str
    reason: str
    resolved_ip: str | None = None
    approval_source: str | None = None


# --- Etap 2: inwentarz, findingi, feed zagrożeń, kolejka weryfikacji, skany ---

RiskLevel = Literal["krytyczny", "wysoki", "średni", "niski"]
FindingStatus = Literal[
    "open", "acknowledged", "in_progress", "resolved", "accepted_risk", "false_positive"
]


class AssetRef(OrmModel):
    id: uuid.UUID
    name: str
    type: AnyAssetType
    exposure: Exposure
    criticality: int
    status: AssetStatus


class AssetImportIn(BaseModel):
    csv: str = Field(min_length=1, max_length=2_000_000)


class AssetImportOut(BaseModel):
    created: int
    updated: int
    unchanged: int
    errors: list[str]


class SoftwareOut(OrmModel):
    id: uuid.UUID
    product: str
    version: str
    port: int | None
    protocol: str | None
    raw_banner: str | None
    cpe_vendor: str | None
    cpe_product: str | None
    match_status: str
    match_method: str | None
    match_confidence: float
    source: str
    last_seen: datetime


class AssetHistoryOut(OrmModel):
    id: uuid.UUID
    change: str
    diff: dict[str, Any]
    created_at: datetime


class AssetDetailOut(BaseModel):
    asset: AssetOut
    attributes: dict[str, Any]
    software: list[SoftwareOut]
    history: list[AssetHistoryOut]
    active_findings: int


class VulnRef(OrmModel):
    cve_id: str
    cvss_score: float | None
    epss: float | None
    in_kev: bool
    kev_due_date: date | None
    has_public_exploit: bool


class FindingOut(BaseModel):
    id: uuid.UUID
    type: str
    status: FindingStatus
    risk_score: float
    risk_level: RiskLevel
    summary: str
    asset: AssetRef
    vulnerability: VulnRef | None
    product: str | None
    version: str | None
    port: int | None
    fixed_version: str | None
    assignee: str | None
    first_seen: datetime
    last_seen: datetime


class FindingEventOut(OrmModel):
    id: uuid.UUID
    kind: str
    before: dict[str, Any]
    after: dict[str, Any]
    actor: str
    reason: str | None
    created_at: datetime


class FindingDetailOut(FindingOut):
    description: str
    references: list[str]
    kev_required_action: str | None
    risk_breakdown: dict[str, Any]
    evidence: dict[str, Any]
    events: list[FindingEventOut]


class FindingPatchIn(BaseModel):
    status: FindingStatus | None = None
    assignee: str | None = Field(default=None, max_length=255)
    reason: str = Field(default="", max_length=2000)


class AffectedAssetOut(BaseModel):
    finding_id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: str
    risk_score: float
    risk_level: RiskLevel


class ThreatOut(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None
    epss: float | None
    in_kev: bool
    kev_date_added: date | None
    has_public_exploit: bool
    published: datetime | None
    first_ingested: datetime
    is_new: bool
    affected_assets: list[AffectedAssetOut]
    max_risk: float | None


class ThreatFeedOut(BaseModel):
    items: list[ThreatOut]
    total: int
    total_ours: int
    new_total: int
    new_ours: int
    new_since: datetime


class FeedStatusOut(BaseModel):
    feed: str
    mode: str | None
    status: str
    items_new: int
    items_updated: int
    error: str | None
    finished_at: datetime | None


class TaskOut(BaseModel):
    task_id: str
    detail: str


class ReviewItemOut(BaseModel):
    id: uuid.UUID
    cpe: str
    score: float
    method: str
    reason: str
    created_at: datetime
    software: SoftwareOut
    asset: AssetRef


class SignalItemOut(BaseModel):
    """Sygnał bez CPE w kolejce weryfikacji: produkt z KEV dopasowany po nazwie."""

    id: uuid.UUID
    cve_id: str
    source: str
    vendor: str
    product: str
    score: float
    method: str
    reason: str
    kev_due_date: date | None
    created_at: datetime
    software: SoftwareOut
    asset: AssetRef


class SignalDecisionOut(BaseModel):
    decision: str
    findings_created: int


class ReviewDecisionIn(BaseModel):
    accept: bool


class ReviewDecisionOut(BaseModel):
    match_status: str
    findings_created: int


class ScanActionOut(OrmModel):
    id: uuid.UUID
    scan_run_id: uuid.UUID
    asset_id: uuid.UUID | None
    target: str
    tool: str
    rule_name: str
    intrusiveness: int
    status: str
    approval_source: str | None
    scope_decision: str | None
    params: dict[str, Any]
    reason: str
    detail: str | None
    created_at: datetime
    finished_at: datetime | None


class ScanRunOut(OrmModel):
    id: uuid.UUID
    trigger: str
    status: str
    summary: dict[str, Any]
    started_at: datetime
    finished_at: datetime | None
    actions: list[ScanActionOut] = Field(default_factory=list)


class ApprovalIn(BaseModel):
    """Kto zatwierdza, wynika z tokenu; klient podaje tylko uzasadnienie."""

    reason: str = Field(min_length=3, max_length=2000)


class NotificationOut(OrmModel):
    id: uuid.UUID
    finding_id: uuid.UUID | None
    rule_name: str
    channel: str
    status: str
    payload: dict[str, Any]
    created_at: datetime


class StatsOut(BaseModel):
    assets_total: int
    assets_by_status: dict[str, int]
    findings_active: int
    findings_by_level: dict[str, int]
    kev_active: int
    review_queue: int
    awaiting_approval: int
    notifications_today: int
    last_scan: ScanRunOut | None
    feeds: list[FeedStatusOut]
