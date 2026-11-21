"""Własne sygnatury detekcyjne dodawane w konsoli.

Revision ID: 0016
Revises: 0015
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "custom_signature",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("signature_id", sa.String(length=64), nullable=False),
        sa.Column(
            "definition",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.String(length=255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custom_signature")),
        sa.UniqueConstraint("signature_id", name=op.f("uq_custom_signature_signature_id")),
    )


def downgrade() -> None:
    op.drop_table("custom_signature")
