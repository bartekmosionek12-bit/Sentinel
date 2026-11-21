"""Organizacja, ludzie i źródła inwentarza (ARCHITECTURE §7.1, Etap 6, #18).

Dane osobowe (imię i nazwisko, stanowisko) są tylko w `Person`. API pokazuje je wyłącznie z
uprawnieniem `personal_data:view`; eksporty i zewnętrzny LLM dostają pseudonim
(„Pracownik #142”, `pseudonym_no`).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk, utcnow
from app.models.inventory import _in

PERSON_SOURCES = ("ad", "entra", "mdm", "import")
ASSIGNMENT_ROLES = ("user", "owner")
ASSET_SOURCES = ("scan", "csv", "ad", "entra", "mdm", "cmdb", "dhcp", "dns", "cloud")
# Źródła, które znaczą „organizacja wie o tym urządzeniu”. Widziany tylko w sieci (skan, DHCP,
# DNS), bez żadnego z nich, to kandydat na shadow IT.
KNOWN_SOURCES = ("csv", "ad", "entra", "mdm", "cmdb", "cloud")


class OrgUnit(Base):
    __tablename__ = "org_unit"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(String(255))
    external_id: Mapped[str] = mapped_column(String(255), unique=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("org_unit.id", ondelete="SET NULL"), index=True
    )


class Location(Base):
    __tablename__ = "location"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(String(255))
    external_id: Mapped[str] = mapped_column(String(255), unique=True)
    address: Mapped[str | None] = mapped_column(String(255))


class NetworkSegment(Base):
    __tablename__ = "network_segment"

    id: Mapped[UuidPk]
    name: Mapped[str] = mapped_column(String(255))
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("location.id", ondelete="SET NULL"), index=True
    )


class Person(Base):
    __tablename__ = "person"
    __table_args__ = (
        UniqueConstraint("source", "external_id"),
        CheckConstraint(_in("source", PERSON_SOURCES), name="source_valid"),
    )

    id: Mapped[UuidPk]
    full_name: Mapped[str] = mapped_column(String(255))
    job_title: Mapped[str | None] = mapped_column(String(255))
    org_unit_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("org_unit.id", ondelete="SET NULL"), index=True
    )
    source: Mapped[str] = mapped_column(String(16))
    external_id: Mapped[str] = mapped_column(String(255))
    pseudonym_no: Mapped[int] = mapped_column(unique=True)
    active: Mapped[bool] = mapped_column(default=True)
    left_at: Mapped[datetime | None]
    created_at: Mapped[CreatedAt]


class AssetAssignment(Base):
    __tablename__ = "asset_assignment"
    __table_args__ = (
        UniqueConstraint("asset_id", "person_id", "role"),
        CheckConstraint(_in("role", ASSIGNMENT_ROLES), name="role_valid"),
    )

    id: Mapped[UuidPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), index=True
    )
    person_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("person.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(8))
    valid_from: Mapped[date | None]
    valid_to: Mapped[date | None]


class AssetSource(Base):
    """Które źródło widziało zasób i kiedy. Z tego wynika `in_cmdb` i reguła shadow IT."""

    __tablename__ = "asset_source"
    __table_args__ = (
        UniqueConstraint("asset_id", "source"),
        CheckConstraint(_in("source", ASSET_SOURCES), name="source_valid"),
    )

    id: Mapped[UuidPk]
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(16))
    external_id: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)


class CoverageSnapshot(Base):
    """Metryka pokrycia inwentarza (§8.6), jeden wiersz na dzień: szereg czasowy na wykres."""

    __tablename__ = "coverage_snapshot"

    id: Mapped[UuidPk]
    day: Mapped[date] = mapped_column(unique=True)
    assets_total: Mapped[int]
    with_owner: Mapped[int]
    scanned_recently: Mapped[int]
    known_version: Mapped[int]
    unknown_devices: Mapped[int]
    open_findings: Mapped[int] = mapped_column(default=0)
    critical_findings: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[CreatedAt]
