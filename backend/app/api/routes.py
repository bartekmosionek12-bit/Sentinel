"""Routery REST API (Etap 1: zdrowie, zasoby, audit log, zakres)."""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

import redis
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.api.deps import ScopeGuardDep, SessionDep, SettingsDep
from app.api.schemas import (
    AnyAssetType,
    AssetIn,
    AssetOut,
    AssetStatus,
    AuditChainOut,
    AuditLogOut,
    HealthOut,
    Page,
    ScopeCheckIn,
    ScopeCheckOut,
    ScopeOut,
)
from app.core import audit
from app.core.scope_guard import Intrusiveness, ScopeError
from app.iam.deps import public_endpoint, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.inventory.service import asset_fingerprint
from app.models import Asset, AuditLog

logger = logging.getLogger("sentinel.api")
router = APIRouter(prefix="/api", route_class=RedactingRoute)

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0)]


@router.get(
    "/health", response_model=HealthOut, tags=["system"], dependencies=[Depends(public_endpoint())]
)
def health(session: SessionDep, settings: SettingsDep) -> HealthOut:
    database = True
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        database = False
    queue = True
    try:
        client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1)
        client.ping()
        client.close()
    except redis.RedisError:
        queue = False
    return HealthOut(
        status="ok" if database and queue else "degraded",
        version=__version__,
        database=database,
        redis=queue,
        demo_mode=settings.demo_mode,
    )


@router.get(
    "/assets",
    response_model=Page[AssetOut],
    tags=["inwentarz"],
    dependencies=[Depends(require("inventory:read"))],
)
def list_assets(
    session: SessionDep,
    type: AnyAssetType | None = None,
    status_filter: Annotated[AssetStatus | None, Query(alias="status")] = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> Page[AssetOut]:
    query = select(Asset)
    if type:
        query = query.where(Asset.type == type)
    if status_filter:
        query = query.where(Asset.status == status_filter)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(Asset.name).limit(limit).offset(offset)).all()
    return Page[AssetOut](
        items=[AssetOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.post(
    "/assets", response_model=AssetOut, status_code=status.HTTP_201_CREATED, tags=["inwentarz"]
)
def create_asset(
    payload: AssetIn,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("inventory:write"))],
) -> AssetOut:
    fingerprint = asset_fingerprint(payload.type, payload.name)
    if session.scalar(select(Asset.id).where(Asset.fingerprint == fingerprint)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Zasób o tej nazwie i typie już istnieje")
    asset = Asset(fingerprint=fingerprint, **payload.model_dump())
    session.add(asset)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="asset_created",
            reason="Zasób dodany ręcznie przez API",
            inputs=payload.model_dump(),
            object_type="asset",
            object_id=str(asset.id),
        ),
    )
    return AssetOut.model_validate(asset)


@router.get(
    "/assets/{asset_id}",
    response_model=AssetOut,
    tags=["inwentarz"],
    dependencies=[Depends(require("inventory:read"))],
)
def get_asset(asset_id: uuid.UUID, session: SessionDep) -> AssetOut:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono zasobu")
    return AssetOut.model_validate(asset)


@router.get(
    "/audit-log",
    response_model=Page[AuditLogOut],
    tags=["audit"],
    dependencies=[Depends(require("audit:read"))],
)
def list_audit_log(
    session: SessionDep,
    action: str | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> Page[AuditLogOut]:
    query = select(AuditLog)
    if action:
        query = query.where(AuditLog.action == action)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(AuditLog.id.desc()).limit(limit).offset(offset)).all()
    return Page[AuditLogOut](
        items=[AuditLogOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get(
    "/audit-log/verify",
    response_model=AuditChainOut,
    tags=["audit"],
    dependencies=[Depends(require("audit:read"))],
)
def verify_audit_log(session: SessionDep) -> AuditChainOut:
    result = audit.verify_chain(session)
    return AuditChainOut(
        ok=result.ok,
        entries=result.entries,
        broken_at_id=result.broken_at_id,
        detail=result.detail,
    )


@router.get(
    "/scope",
    response_model=ScopeOut,
    tags=["zakres"],
    dependencies=[Depends(require("scope:read"))],
)
def get_scope(guard: ScopeGuardDep, settings: SettingsDep) -> ScopeOut:
    config = guard.config
    return ScopeOut(
        allowed_domains=list(config.allowed_domains),
        allowed_cidrs=[str(n) for n in config.allowed_cidrs],
        denied_domains=list(config.denied_domains),
        denied_cidrs=[str(n) for n in config.denied_cidrs],
        default_rate_per_minute=config.default_rate_per_minute,
        scan_packets_per_second=config.scan_packets_per_second,
        scan_workers=config.scan_workers,
        demo_mode=settings.demo_mode,
        demo_lab_cidr=settings.demo_lab_cidr,
        demo_approval_expires_at=settings.demo_approval_expires_at,
    )


@router.post(
    "/scope/check",
    response_model=ScopeCheckOut,
    tags=["zakres"],
    dependencies=[Depends(require("scope:manage"))],
)
def check_scope(payload: ScopeCheckIn, guard: ScopeGuardDep) -> ScopeCheckOut:
    """Podgląd decyzji bramy dla celu. Niczego nie skanuje; decyzja trafia do audit logu."""
    try:
        scoped = guard.authorize(
            payload.target,
            tool="scope_check",
            intrusiveness=Intrusiveness(payload.intrusiveness),
            rule_name="manual_scope_check",
            dry_run=True,
        )
    except ScopeError as error:
        return ScopeCheckOut(
            target=payload.target, allowed=False, decision=error.code, reason=error.reason
        )
    return ScopeCheckOut(
        target=payload.target,
        allowed=True,
        decision="scope_allowed",
        reason="Cel w zakresie",
        resolved_ip=scoped.address,
        approval_source=scoped.approval_source,
    )
