"""Zależności FastAPI."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.audit import DbAuditSink
from app.core.config import Settings, get_settings
from app.core.db import get_session, get_sessionmaker
from app.core.scope_guard import ScopeConfig, ScopeGuard, SeedDemoApproval


def build_scope_guard(settings: Settings) -> ScopeGuard:
    return ScopeGuard(
        ScopeConfig.from_file(settings.scope_file),
        audit=DbAuditSink(get_sessionmaker()),
        seed_demo=SeedDemoApproval(
            demo_mode=settings.demo_mode,
            lab_network=settings.demo_lab_network,
            expires_at=settings.demo_approval_expires_at,
        ),
    )


@lru_cache
def get_scope_guard() -> ScopeGuard:
    return build_scope_guard(get_settings())


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
ScopeGuardDep = Annotated[ScopeGuard, Depends(get_scope_guard)]
