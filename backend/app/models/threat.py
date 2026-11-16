"""Podatności i zakresy podatnych wersji."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UuidPk, utcnow


class Vulnerability(Base):
    __tablename__ = "vulnerability"

    id: Mapped[UuidPk]
    cve_id: Mapped[str] = mapped_column(String(32), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None]
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    epss: Mapped[float | None]
    epss_percentile: Mapped[float | None]
    in_kev: Mapped[bool] = mapped_column(default=False, index=True)
    kev_due_date: Mapped[date | None]
    kev_date_added: Mapped[date | None]
    kev_vendor_project: Mapped[str | None] = mapped_column(String(255))
    kev_product: Mapped[str | None] = mapped_column(String(255))
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    has_public_exploit: Mapped[bool] = mapped_column(default=False)
    references: Mapped[list[Any]] = mapped_column(default=list)
    source: Mapped[str] = mapped_column(String(20), default="nvd")
    published: Mapped[datetime | None] = mapped_column(index=True)
    last_modified: Mapped[datetime | None]
    first_ingested: Mapped[datetime] = mapped_column(default=utcnow, index=True)

    affected: Mapped[list[VulnAffected]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class VulnAffected(Base):
    """Spłaszczony zakres wersji z konfiguracji NVD (jeden wiersz na zakres)."""

    __tablename__ = "vuln_affected"
    __table_args__ = (Index("ix_vuln_affected_vendor_product", "cpe_vendor", "cpe_product"),)

    id: Mapped[UuidPk]
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability.id", ondelete="CASCADE"), index=True
    )
    cpe_vendor: Mapped[str] = mapped_column(String(255))
    cpe_product: Mapped[str] = mapped_column(String(255))
    version_exact: Mapped[str | None] = mapped_column(String(128))
    start_including: Mapped[str | None] = mapped_column(String(128))
    start_excluding: Mapped[str | None] = mapped_column(String(128))
    end_including: Mapped[str | None] = mapped_column(String(128))
    end_excluding: Mapped[str | None] = mapped_column(String(128))
    fixed_version: Mapped[str | None] = mapped_column(String(128))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="affected")
