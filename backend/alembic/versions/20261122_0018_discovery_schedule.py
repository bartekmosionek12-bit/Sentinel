"""Harmonogram discovery: okno czasowe, częstotliwość, wstrzymanie i wznowienie przebiegu.

Revision ID: 0018
Revises: 0017
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "discovery_schedule",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("targets", sa.Text(), nullable=False),
        sa.Column("settings", JSONB, nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("window_start", sa.String(length=5), nullable=False),
        sa.Column("window_end", sa.String(length=5), nullable=False),
        sa.Column("days", JSONB, nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resume_run_id", sa.Uuid(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_discovery_schedule")),
    )
    with op.batch_alter_table("discovery_run") as batch:
        batch.add_column(sa.Column("schedule_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("resume_of", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("deadline", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("remaining", sa.Text(), nullable=True))
        batch.create_index(op.f("ix_discovery_run_schedule_id"), ["schedule_id"])
        batch.create_foreign_key(
            op.f("fk_discovery_run_schedule_id_discovery_schedule"),
            "discovery_schedule",
            ["schedule_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("discovery_run") as batch:
        batch.drop_constraint(
            op.f("fk_discovery_run_schedule_id_discovery_schedule"), type_="foreignkey"
        )
        batch.drop_index(op.f("ix_discovery_run_schedule_id"))
        for column in ("remaining", "deadline", "resume_of", "schedule_id"):
            batch.drop_column(column)
    op.drop_table("discovery_schedule")
