"""Wspólne fixture'y: baza SQLite w pamięci, bez sieci, bez Redisa, bez modelu."""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import ip_address

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_scope_guard
from app.core.audit import AuditEvent, DbAuditSink
from app.core.db import get_session
from app.core.scope_guard import IPAddress, ScopeConfig, ScopeGuard
from app.main import create_app
from app.models import Base


class FakeResolver:
    """Resolver bez sieci: zwraca adresy z podanej mapy."""

    def __init__(self, mapping: dict[str, list[str]] | None = None) -> None:
        self.mapping = mapping or {}
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> list[IPAddress]:
        self.calls.append(hostname)
        return [ip_address(a) for a in self.mapping.get(hostname, [])]


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def __call__(self, event: AuditEvent) -> None:
        self.events.append(event)

    @property
    def actions(self) -> list[str]:
        return [e.action for e in self.events]


@pytest.fixture
def session_factory() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as db:
        yield db


@pytest.fixture
def audit_sink() -> MemoryAudit:
    return MemoryAudit()


@pytest.fixture
def client(session_factory: sessionmaker[Session]) -> Iterator[TestClient]:
    app = create_app()

    def _session() -> Iterator[Session]:
        with session_factory() as db:
            yield db
            db.commit()

    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.0/24"]}}),
        audit=DbAuditSink(session_factory),
        resolver=FakeResolver(),
    )
    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_scope_guard] = lambda: guard
    with TestClient(app) as test_client:
        yield test_client
