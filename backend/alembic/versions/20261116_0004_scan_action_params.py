"""scan_action: parametry, powód i wynik akcji

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_action",
        sa.Column(
            "params",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "scan_action", sa.Column("reason", sa.Text(), server_default="", nullable=False)
    )
    op.add_column("scan_action", sa.Column("detail", sa.Text(), nullable=True))
    op.add_column(
        "scan_action", sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scan_action", "finished_at")
    op.drop_column("scan_action", "detail")
    op.drop_column("scan_action", "reason")
    op.drop_column("scan_action", "params")
