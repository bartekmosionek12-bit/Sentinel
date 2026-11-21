"""Etap 4b: raporty dwuwarstwowe i skrzynka menedżera

- `report`: światło i fakty z reguł (kod), warstwa „W skrócie” (model albo szablon) i
  warstwa techniczna; teksty z tokenami `asset_<n>`, `person_<n>` zamiast nazw.
- `report_delivery`: doręczenie do skrzynek roli (np. manager), `report_read`: odczyt przez osobę.
- `notification.report_id`: powiadomienie wskazujące raport (np. zero-day).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "report",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("scope", JSON, nullable=False),
        sa.Column("light", sa.String(length=8), nullable=False),
        sa.Column("light_reason", sa.Text(), nullable=False),
        sa.Column("facts", JSON, nullable=False),
        sa.Column("entities", JSON, nullable=False),
        sa.Column("summary", JSON, nullable=False),
        sa.Column("summary_source", sa.String(length=10), nullable=False),
        sa.Column("summary_validation", sa.String(length=12), nullable=False),
        sa.Column("summary_model", sa.String(length=128), nullable=True),
        sa.Column("summary_problems", JSON, nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=True),
        sa.Column("technical", JSON, nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("kind IN ('assessment', 'zero_day')", name=op.f("ck_report_kind_valid")),
        sa.CheckConstraint(
            "light IN ('red', 'yellow', 'green')", name=op.f("ck_report_light_valid")
        ),
        sa.CheckConstraint(
            "summary_source IN ('model', 'template')", name=op.f("ck_report_summary_source_valid")
        ),
        sa.CheckConstraint(
            "summary_validation IN ('none', 'passed', 'rejected', 'unavailable')",
            name=op.f("ck_report_summary_validation_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report")),
    )
    op.create_index(op.f("ix_report_kind"), "report", ["kind"], unique=False)
    op.create_table(
        "report_delivery",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_role", sa.String(length=32), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["report.id"],
            name=op.f("fk_report_delivery_report_id_report"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_delivery")),
        sa.UniqueConstraint(
            "report_id",
            "recipient_role",
            "channel",
            name=op.f("uq_report_delivery_report_id_recipient_role_channel"),
        ),
    )
    op.create_index(
        op.f("ix_report_delivery_recipient_role"),
        "report_delivery",
        ["recipient_role"],
        unique=False,
    )
    op.create_index(
        op.f("ix_report_delivery_report_id"), "report_delivery", ["report_id"], unique=False
    )
    op.create_table(
        "report_read",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["report.id"],
            name=op.f("fk_report_read_report_id_report"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["iam_user.id"],
            name=op.f("fk_report_read_user_id_iam_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_read")),
        sa.UniqueConstraint("report_id", "user_id", name=op.f("uq_report_read_report_id_user_id")),
    )
    op.create_index(op.f("ix_report_read_report_id"), "report_read", ["report_id"], unique=False)
    op.create_index(op.f("ix_report_read_user_id"), "report_read", ["user_id"], unique=False)
    op.add_column("notification", sa.Column("report_id", sa.Uuid(), nullable=True))
    op.create_index(op.f("ix_notification_report_id"), "notification", ["report_id"], unique=False)
    op.create_foreign_key(
        op.f("fk_notification_report_id_report"),
        "notification",
        "report",
        ["report_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_notification_report_id_report"), "notification", type_="foreignkey")
    op.drop_index(op.f("ix_notification_report_id"), table_name="notification")
    op.drop_column("notification", "report_id")
    op.drop_index(op.f("ix_report_read_user_id"), table_name="report_read")
    op.drop_index(op.f("ix_report_read_report_id"), table_name="report_read")
    op.drop_table("report_read")
    op.drop_index(op.f("ix_report_delivery_report_id"), table_name="report_delivery")
    op.drop_index(op.f("ix_report_delivery_recipient_role"), table_name="report_delivery")
    op.drop_table("report_delivery")
    op.drop_index(op.f("ix_report_kind"), table_name="report")
    op.drop_table("report")
