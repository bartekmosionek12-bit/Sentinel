"""Kopia ról i uprawnień z `rules/roles.yaml` w bazie (podgląd, raporty, klucze obce).

Źródłem prawdy jest plik w Git; tabela jest nadpisywana przy każdym starcie API.
"""

from __future__ import annotations

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.iam.rbac import RoleCatalog
from app.models import Permission, Role, RolePermission


def sync_catalog(session: Session, catalog: RoleCatalog) -> dict[str, int]:
    session.execute(delete(RolePermission))
    for name in set(session.scalars(Role.__table__.select().with_only_columns(Role.name))) - set(
        catalog.roles
    ):
        session.execute(delete(Role).where(Role.name == name))
    for name in set(
        session.scalars(Permission.__table__.select().with_only_columns(Permission.name))
    ) - set(catalog.permissions):
        session.execute(delete(Permission).where(Permission.name == name))
    for permission in catalog.permissions.values():
        session.merge(
            Permission(name=permission.name, description=permission.description, mfa=permission.mfa)
        )
    for role in catalog.roles.values():
        session.merge(Role(name=role.name, description=role.description, kind=role.kind))
    session.flush()
    links = [
        RolePermission(role_name=role.name, permission_name=permission)
        for role in catalog.roles.values()
        for permission in sorted(role.permissions)
    ]
    session.add_all(links)
    session.flush()
    return {
        "roles": len(catalog.roles),
        "permissions": len(catalog.permissions),
        "links": len(links),
    }
