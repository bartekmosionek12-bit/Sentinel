"""Cele skanowania i nadpisania wyników.

Revision ID: 0013
Revises: 0012
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_target",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("target", sa.String(255), unique=True, nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scan_result_override",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("field", sa.String(32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("host", "field", name="uq_scan_override_host_field"),
    )
    op.create_index("ix_scan_result_override_host", "scan_result_override", ["host"])


def downgrade() -> None:
    op.drop_index("ix_scan_result_override_host", table_name="scan_result_override")
    op.drop_table("scan_result_override")
    op.drop_table("scan_target")
