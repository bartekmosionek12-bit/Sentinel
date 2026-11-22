"""Discovery dużej infrastruktury (brief AGH): przebiegi, paczki, obserwacje hostów, nadpisania.

Obserwacja to stan jednego hosta w jednym przebiegu (usługi, HTTP, flagi). Porównanie dwóch
przebiegów i stan hosta (aktywny, niestabilny, niepotwierdzony, nieaktywny) liczy kod z
obserwacji. Nadpisania człowieka są osobną warstwą kluczowaną adresem, więc kolejny skan ich
nie kasuje.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import EncryptedJSON, EncryptedText
from app.models.base import Base, CreatedAt, UuidPk, utcnow


class DiscoveryRun(Base):
    __tablename__ = "discovery_run"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="queued")
    source: Mapped[str] = mapped_column(String(20), default="scan")  # scan | import
    targets: Mapped[list[str]] = mapped_column(EncryptedJSON, default=list)
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    created_at: Mapped[CreatedAt]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    addresses_total: Mapped[int] = mapped_column(Integer, default=0)
    addresses_done: Mapped[int] = mapped_column(Integer, default=0)
    batches_done: Mapped[int] = mapped_column(Integer, default=0)
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    eta_seconds: Mapped[float | None] = mapped_column(Float)
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)


class DiscoveryBatch(Base):
    __tablename__ = "discovery_batch"

    id: Mapped[UuidPk]
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("discovery_run.id", ondelete="CASCADE"), index=True
    )
    target: Mapped[str] = mapped_column(String(64))
    addresses: Mapped[int] = mapped_column(Integer)
    phase: Mapped[str] = mapped_column(String(20), default="sweep")  # sweep | services
    status: Mapped[str] = mapped_column(String(20), default="done")
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str | None] = mapped_column(Text)
    finished_at: Mapped[datetime] = mapped_column(default=utcnow)


class Observation(Base):
    __tablename__ = "observation"
    __table_args__ = (UniqueConstraint("run_id", "ip"),)

    id: Mapped[UuidPk]
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("discovery_run.id", ondelete="CASCADE"), index=True
    )
    ip: Mapped[str] = mapped_column(String(64), index=True)
    # Wyniki skanu: szyfrowane w spoczynku (app/core/crypto.py).
    hostname: Mapped[str | None] = mapped_column(EncryptedText)
    services: Mapped[list[Any]] = mapped_column(EncryptedJSON, default=list)
    http: Mapped[list[Any]] = mapped_column(EncryptedJSON, default=list)
    flags: Mapped[list[Any]] = mapped_column(EncryptedJSON, default=list)
    created_at: Mapped[CreatedAt]


class ObservationOverride(Base):
    """Ręczna zmiana wyniku (warstwa nadpisań). Kluczem jest adres i pole, nie przebieg."""

    __tablename__ = "observation_override"
    __table_args__ = (UniqueConstraint("ip", "field"),)

    id: Mapped[UuidPk]
    ip: Mapped[str] = mapped_column(String(64), index=True)
    field: Mapped[str] = mapped_column(String(40))
    value: Mapped[Any] = mapped_column(EncryptedJSON, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class DefectDojoExport(Base):
    """Co już wysłaliśmy do DefectDojo (deduplikacja po unikalnym identyfikatorze)."""

    __tablename__ = "defectdojo_export"

    id: Mapped[UuidPk]
    unique_id: Mapped[str] = mapped_column(String(200), unique=True)
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("discovery_run.id", ondelete="SET NULL")
    )
    remote_id: Mapped[int | None] = mapped_column(Integer)
    exported_by: Mapped[str] = mapped_column(String(255))
    exported_at: Mapped[datetime] = mapped_column(default=utcnow)


class CustomSignature(Base):
    """Własna sygnatura detekcyjna dodana w konsoli (obok wbudowanych z rules/signatures.yaml).

    `definition` ma ten sam kształt co pozycja w pliku YAML i przechodzi ten sam walidator.
    """

    __tablename__ = "custom_signature"

    id: Mapped[UuidPk]
    signature_id: Mapped[str] = mapped_column(String(64), unique=True)
    definition: Mapped[dict[str, Any]] = mapped_column(default=dict)
    updated_by: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)
