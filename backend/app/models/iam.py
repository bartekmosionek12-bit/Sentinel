"""Tożsamość i uprawnienia (Etap 4).

Role i uprawnienia są kopią `rules/roles.yaml` (źródło prawdy w Git), synchronizowaną przy
starcie API, żeby dało się je odpytać i powiązać. Użytkownicy powstają przy pierwszym
wywołaniu API z ważnym tokenem Keycloaka; hasła i drugi składnik trzyma wyłącznie Keycloak.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, CreatedAt, UuidPk
from app.models.inventory import _in

PRINCIPAL_KINDS = ("human", "agent", "system")


class User(Base):
    __tablename__ = "iam_user"
    __table_args__ = (CheckConstraint(_in("kind", PRINCIPAL_KINDS), name="kind_valid"),)

    id: Mapped[UuidPk]
    # `sub` z tokenu Keycloaka: stały identyfikator konta.
    subject: Mapped[str] = mapped_column(String(255), unique=True)
    username: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    kind: Mapped[str] = mapped_column(String(16), default="human")
    # Role z ostatniego tokenu (podgląd w konsoli); o dostępie decyduje zawsze bieżący token.
    roles: Mapped[list[str]] = mapped_column(default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[CreatedAt]
    last_seen_at: Mapped[datetime | None]


class Role(Base):
    __tablename__ = "iam_role"
    __table_args__ = (CheckConstraint(_in("kind", PRINCIPAL_KINDS), name="kind_valid"),)

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16), default="human")


class Permission(Base):
    __tablename__ = "iam_permission"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    mfa: Mapped[bool] = mapped_column(Boolean, default=False)


class RolePermission(Base):
    __tablename__ = "iam_role_permission"

    role_name: Mapped[str] = mapped_column(
        ForeignKey("iam_role.name", ondelete="CASCADE"), primary_key=True
    )
    permission_name: Mapped[str] = mapped_column(
        ForeignKey("iam_permission.name", ondelete="CASCADE"), primary_key=True
    )


__all__ = ["PRINCIPAL_KINDS", "Permission", "Role", "RolePermission", "User", "uuid"]
