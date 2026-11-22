"""Trzy warstwy skanowania podatności i delegacje dostępu do nich (docs/WARSTWY.md).

* Warstwa 1: deterministyczny skan narzędziami red team (`RedteamRun`, `RedteamFinding`).
* Warstwa 2: analiza logów warstwy 1 przez model językowy (`RedteamAnalysis`).
* Warstwa 3: autonomiczny agent AI (istniejące `AgentTask`).

Domyślnie każdą warstwę uruchamia tylko administrator. `LayerDelegation` daje konkretnej
osobie jedną warstwę na konkretnej podsieci w konkretnym oknie czasu.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedJSON, EncryptedText
from app.models.base import Base, CreatedAt, UuidPk


class LayerDelegation(Base):
    """Delegacja: osoba × warstwa × podsieci × okno czasu. Odwołanie zostawia ślad."""

    __tablename__ = "iam_layer_delegation"
    __table_args__ = (CheckConstraint("layer BETWEEN 1 AND 3", name="layer_range"),)

    id: Mapped[UuidPk]
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("iam_user.id", ondelete="CASCADE"), index=True
    )
    layer: Mapped[int] = mapped_column(Integer)
    # CIDR-y (jednostka/podsieć); każdy musi leżeć w zakresie skanowania.
    scope: Mapped[list[str]] = mapped_column(EncryptedJSON, default=list)
    valid_from: Mapped[datetime]
    valid_until: Mapped[datetime]
    reason: Mapped[str] = mapped_column(Text, default="")
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[CreatedAt]
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[str | None] = mapped_column(String(255))


class RedteamRun(Base):
    """Przebieg warstwy 1: ręcznie wywołany, deterministyczny skan podatności."""

    __tablename__ = "redteam_run"

    id: Mapped[UuidPk]
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|failed
    targets: Mapped[list[str]] = mapped_column(EncryptedJSON, default=list)
    reason: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(255))
    # Delegacja, na podstawie której uruchomiono (puste = uprawnienie z roli).
    delegation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("iam_layer_delegation.id", ondelete="SET NULL")
    )
    created_at: Mapped[CreatedAt]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    hosts: Mapped[int] = mapped_column(Integer, default=0)
    # Log narzędzi (polecenia, czasy, liczby wyników) dla warstwy 2 i audytu.
    log: Mapped[list[Any]] = mapped_column(EncryptedJSON, default=list)
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)


class RedteamFinding(Base):
    """Jedna podatność na jednym punkcie końcowym. `group_key` łączy te same problemy."""

    __tablename__ = "redteam_finding"

    id: Mapped[UuidPk]
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("redteam_run.id", ondelete="CASCADE"), index=True
    )
    check_id: Mapped[str] = mapped_column(String(64))
    group_key: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))  # critical|high|medium|low|info
    category: Mapped[str] = mapped_column(String(32), default="")
    ip: Mapped[str] = mapped_column(EncryptedText)
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str] = mapped_column(String(64), default="")
    tool: Mapped[str] = mapped_column(String(64), default="nmap")
    evidence: Mapped[list[str]] = mapped_column(EncryptedJSON, default=list)


class RedteamAnalysis(Base):
    """Warstwa 2: zalecenia do przebiegu warstwy 1 (model lokalny albo jawny szablon)."""

    __tablename__ = "redteam_analysis"

    id: Mapped[UuidPk]
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("redteam_run.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|failed
    source: Mapped[str] = mapped_column(String(16), default="")  # model | template
    model: Mapped[str | None] = mapped_column(String(128))
    requested_by: Mapped[str] = mapped_column(String(255))
    content: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON, default=dict)
    created_at: Mapped[CreatedAt]
    finished_at: Mapped[datetime | None]
    error: Mapped[str | None] = mapped_column(Text)


__all__ = ["LayerDelegation", "RedteamAnalysis", "RedteamFinding", "RedteamRun"]
