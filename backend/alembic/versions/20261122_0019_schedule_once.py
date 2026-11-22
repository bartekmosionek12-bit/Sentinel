"""Harmonogram jednorazowy: przebieg startuje i kończy się w zadanym momencie.

Revision ID: 0019
Revises: 0018
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("discovery_schedule") as batch:
        batch.add_column(sa.Column("start_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("end_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("discovery_schedule") as batch:
        batch.drop_column("end_at")
        batch.drop_column("start_at")
