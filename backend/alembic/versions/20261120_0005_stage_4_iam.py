"""Etap 4: tożsamość i uprawnienia, aktor w audycie, poziomy inwazyjności L1–L3

- `iam_user`, `iam_role`, `iam_permission`, `iam_role_permission` zastępują `app_user`
  (logowanie i hasła są w Keycloaku; tu tylko konta widziane w tokenach i kopia roles.yaml).
- `scan_action.approved_by` wskazuje `iam_user`.
- `scan_action.intrusiveness`: L1 (pasywne i lekkie), L2 (inwazyjne), L3 (red team).
  Dotychczasowe L0 (pasywne) łączy się z L1, więc 0 → 1; L1 i L2 zachowują numery.
- `audit_log`: rodzaj i identyfikator aktora, `on_behalf_of`, identyfikator żądania oraz
  wersja formatu skrótu. Istniejące wpisy dostają `hash_version = 1` i weryfikują się po
  starym wzorze; nowe są w formacie 2. Dodanie kolumn nie zmienia istniejących wierszy, więc
  nie narusza triggera „tylko do dopisywania”.
- schematu `keycloak` ta migracja nie tworzy: zakłada go `infra/postgres/init_roles.sql`
  (usługa db-init) z osobnym właścicielem, do którego użytkownik aplikacji nie ma dostępu.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "iam_user",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("roles", JSON, nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('human', 'agent', 'system')", name=op.f("ck_iam_user_kind_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_iam_user")),
        sa.UniqueConstraint("subject", name=op.f("uq_iam_user_subject")),
    )
    op.create_index(op.f("ix_iam_user_username"), "iam_user", ["username"], unique=False)
    op.create_table(
        "iam_role",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.CheckConstraint(
            "kind IN ('human', 'agent', 'system')", name=op.f("ck_iam_role_kind_valid")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_iam_role")),
    )
    op.create_table(
        "iam_permission",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mfa", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_iam_permission")),
    )
    op.create_table(
        "iam_role_permission",
        sa.Column("role_name", sa.String(length=64), nullable=False),
        sa.Column("permission_name", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_name"],
            ["iam_permission.name"],
            name=op.f("fk_iam_role_permission_permission_name_iam_permission"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_name"],
            ["iam_role.name"],
            name=op.f("fk_iam_role_permission_role_name_iam_role"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "role_name", "permission_name", name=op.f("pk_iam_role_permission")
        ),
    )

    # Zatwierdzający: z app_user (nieużywanej poza schematem) na iam_user.
    op.drop_constraint(
        op.f("fk_scan_action_approved_by_app_user"), "scan_action", type_="foreignkey"
    )
    op.execute("UPDATE scan_action SET approved_by = NULL")
    op.create_foreign_key(
        op.f("fk_scan_action_approved_by_iam_user"),
        "scan_action",
        "iam_user",
        ["approved_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_table("app_user")

    # Poziomy L1–L3.
    op.drop_constraint(op.f("ck_scan_action_intrusiveness_range"), "scan_action", type_="check")
    op.execute("UPDATE scan_action SET intrusiveness = 1 WHERE intrusiveness = 0")
    op.create_check_constraint(
        op.f("ck_scan_action_intrusiveness_range"),
        "scan_action",
        "intrusiveness BETWEEN 1 AND 3",
    )

    # Audyt w formacie 2.
    op.add_column("audit_log", sa.Column("actor_type", sa.String(length=16), nullable=True))
    op.add_column("audit_log", sa.Column("actor_id", sa.String(length=255), nullable=True))
    op.add_column("audit_log", sa.Column("on_behalf_of", sa.String(length=255), nullable=True))
    op.add_column("audit_log", sa.Column("request_id", sa.String(length=64), nullable=True))
    op.add_column(
        "audit_log",
        sa.Column("hash_version", sa.Integer(), server_default="1", nullable=False),
    )
    op.create_index(op.f("ix_audit_log_request_id"), "audit_log", ["request_id"], unique=False)


def downgrade() -> None:
    # Dziennik audytu jest tylko do dopisywania: kolumn formatu 2 nie usuwamy, gdy są w nich
    # wpisy, bo stare wiersze straciłyby możliwość weryfikacji skrótu.
    bind = op.get_bind()
    if bind.scalar(sa.text("SELECT count(*) FROM audit_log WHERE hash_version >= 2")):
        raise RuntimeError(
            "audit_log zawiera wpisy w formacie 2; cofnięcie migracji zniszczyłoby łańcuch"
        )
    op.drop_index(op.f("ix_audit_log_request_id"), table_name="audit_log")
    op.drop_column("audit_log", "hash_version")
    op.drop_column("audit_log", "request_id")
    op.drop_column("audit_log", "on_behalf_of")
    op.drop_column("audit_log", "actor_id")
    op.drop_column("audit_log", "actor_type")

    op.drop_constraint(op.f("ck_scan_action_intrusiveness_range"), "scan_action", type_="check")
    # L3 nie istniał: przed cofnięciem traktujemy go jak L2 (najbliższy poziom wymagający zgody).
    op.execute("UPDATE scan_action SET intrusiveness = 2 WHERE intrusiveness = 3")
    op.create_check_constraint(
        op.f("ck_scan_action_intrusiveness_range"),
        "scan_action",
        "intrusiveness BETWEEN 0 AND 2",
    )

    op.create_table(
        "app_user",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('admin', 'manager', 'viewer')", name=op.f("ck_app_user_role_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_user")),
        sa.UniqueConstraint("email", name=op.f("uq_app_user_email")),
    )
    op.drop_constraint(
        op.f("fk_scan_action_approved_by_iam_user"), "scan_action", type_="foreignkey"
    )
    op.execute("UPDATE scan_action SET approved_by = NULL")
    op.create_foreign_key(
        op.f("fk_scan_action_approved_by_app_user"),
        "scan_action",
        "app_user",
        ["approved_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_table("iam_role_permission")
    op.drop_table("iam_permission")
    op.drop_table("iam_role")
    op.drop_index(op.f("ix_iam_user_username"), table_name="iam_user")
    op.drop_table("iam_user")
