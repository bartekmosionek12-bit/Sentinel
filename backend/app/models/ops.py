"""Operacje systemu: skany, feedy, powiadomienia, cache LLM, audit log, użytkownicy."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk, utcnow
from app.models.inventory import _in

USER_ROLES = ("admin", "manager", "viewer")
SCAN_ACTION_STATUSES = (
    "planned",
    "awaiting_approval",
    "running",
    "done",
    "denied",
    "failed",
)
AUDIENCES = ("technical", "operational", "executive")


class AppUser(Base):
    __tablename__ = "app_user"
    __table_args__ = (CheckConstraint(_in("role", USER_ROLES), name="role_valid"),)

    id: Mapped[UuidPk]
    email: Mapped[str] = mapped_column(String(255), unique=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[CreatedAt]


class ScanRun(Base):
    __tablename__ = "scan_run"

    id: Mapped[UuidPk]
    trigger: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="planned")
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None]


class ScanAction(Base):
    """Jedna zaplanowana akcja skanująca wraz z regułą, która ją wywołała."""

    __tablename__ = "scan_action"
    __table_args__ = (
        CheckConstraint(_in("status", SCAN_ACTION_STATUSES), name="status_valid"),
        CheckConstraint("intrusiveness BETWEEN 0 AND 2", name="intrusiveness_range"),
    )

    id: Mapped[UuidPk]
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_run.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("asset.id", ondelete="SET NULL"), index=True
    )
    target: Mapped[str] = mapped_column(String(255))
    tool: Mapped[str] = mapped_column(String(32))
    rule_name: Mapped[str] = mapped_column(String(128))
    intrusiveness: Mapped[int] = mapped_column(default=0)
    status: Mapped[str] = mapped_column(String(20), default="planned", index=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("app_user.id", ondelete="SET NULL")
    )
    approval_source: Mapped[str | None] = mapped_column(String(32))
    scope_decision: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[CreatedAt]


class FeedSync(Base):
    __tablename__ = "feed_sync"

    id: Mapped[UuidPk]
    feed: Mapped[str] = mapped_column(String(20), index=True)
    mode: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(20))
    cursor: Mapped[str | None] = mapped_column(String(128))
    items_new: Mapped[int] = mapped_column(default=0)
    items_updated: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(default=utcnow)
    finished_at: Mapped[datetime | None]


class Notification(Base):
    __tablename__ = "notification"

    id: Mapped[UuidPk]
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding.id", ondelete="SET NULL"), index=True
    )
    rule_name: Mapped[str] = mapped_column(String(128))
    channel: Mapped[str] = mapped_column(String(16))
    group_key: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(20))
    payload: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[CreatedAt]


class LLMCache(Base):
    """Zasada „generuj raz”: jeden tekst na (typ, CVE lub reguła, odbiorca, wersja promptu)."""

    __tablename__ = "llm_cache"
    __table_args__ = (CheckConstraint(_in("audience", AUDIENCES), name="audience_valid"),)

    id: Mapped[UuidPk]
    cache_key: Mapped[str] = mapped_column(String(255), unique=True)
    kind: Mapped[str] = mapped_column(String(20))
    audience: Mapped[str] = mapped_column(String(16))
    prompt_version: Mapped[str] = mapped_column(String(32))
    content: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(128))
    tokens: Mapped[int | None]
    duration_ms: Mapped[int | None]
    validation: Mapped[str] = mapped_column(String(16), default="passed")
    created_at: Mapped[CreatedAt]


class AuditLog(Base):
    """Dziennik tylko do dopisywania z łańcuchem skrótów (patrz app.core.audit)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"), primary_key=True, autoincrement=True
    )
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str | None] = mapped_column(String(64))
    object_id: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text, default="")
    inputs: Mapped[dict[str, Any]] = mapped_column(default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
