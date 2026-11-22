"""Trzy warstwy skanowania podatności i delegacje dostępu w IAM.

Revision ID: 0020
Revises: 0019
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "iam_layer_delegation",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("layer", sa.Integer(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("valid_from", TS, nullable=False),
        sa.Column("valid_until", TS, nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("granted_by", sa.String(length=255), nullable=False),
        sa.Column("granted_at", TS, nullable=False),
        sa.Column("revoked_at", TS, nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.CheckConstraint(
            "layer BETWEEN 1 AND 3", name=op.f("ck_iam_layer_delegation_layer_range")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["iam_user.id"],
            name=op.f("fk_iam_layer_delegation_user_id_iam_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_iam_layer_delegation")),
    )
    op.create_index(op.f("ix_iam_layer_delegation_user_id"), "iam_layer_delegation", ["user_id"])
    op.create_table(
        "redteam_run",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("targets", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("delegation_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("started_at", TS, nullable=True),
        sa.Column("finished_at", TS, nullable=True),
        sa.Column("hosts", sa.Integer(), nullable=False),
        sa.Column("log", sa.Text(), nullable=False),
        sa.Column("summary", JSONB, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["delegation_id"],
            ["iam_layer_delegation.id"],
            name=op.f("fk_redteam_run_delegation_id_iam_layer_delegation"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_redteam_run")),
    )
    op.create_table(
        "redteam_finding",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("check_id", sa.String(length=64), nullable=False),
        sa.Column("group_key", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("ip", sa.Text(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["redteam_run.id"],
            name=op.f("fk_redteam_finding_run_id_redteam_run"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_redteam_finding")),
    )
    op.create_index(op.f("ix_redteam_finding_run_id"), "redteam_finding", ["run_id"])
    op.create_index(op.f("ix_redteam_finding_group_key"), "redteam_finding", ["group_key"])
    op.create_table(
        "redteam_analysis",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("finished_at", TS, nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["redteam_run.id"],
            name=op.f("fk_redteam_analysis_run_id_redteam_run"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_redteam_analysis")),
    )
    op.create_index(op.f("ix_redteam_analysis_run_id"), "redteam_analysis", ["run_id"])


def downgrade() -> None:
    op.drop_table("redteam_analysis")
    op.drop_table("redteam_finding")
    op.drop_table("redteam_run")
    op.drop_table("iam_layer_delegation")
