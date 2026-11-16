"""Schematy wejścia i wyjścia API (Pydantic v2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

AssetType = Literal["host", "domain", "ip", "service", "application"]
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
    type: AssetType
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
    action: str
    object_type: str | None
    object_id: str | None
    reason: str
    inputs: dict[str, Any]
    hash: str
    prev_hash: str


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
    demo_mode: bool
    demo_lab_cidr: str
    demo_approval_expires_at: datetime | None


class ScopeCheckIn(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    intrusiveness: Literal[0, 1, 2] = 1


class ScopeCheckOut(BaseModel):
    target: str
    allowed: bool
    decision: str
    reason: str
    resolved_ip: str | None = None
    approval_source: str | None = None
