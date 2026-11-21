"""Etap 6 (domknięcie Etapu 5): skutki kill switcha poza bazą

- `agent_switch.killed_at`: ostatnie użycie kill switcha (tokeny agenta wydane wcześniej
  `mcp-scanner` odrzuca także po ponownym włączeniu),
- `agent_switch.effects`: wynik wyłączenia klienta w Keycloak i odwołania tokenów w OpenBao,
- `agent_switch.scanner_stopped_at`, `scanner_stopped`: potwierdzenie z `mcp-scanner`.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_switch", sa.Column("killed_at", sa.DateTime(timezone=True)))
    op.add_column(
        "agent_switch",
        sa.Column("effects", sa.JSON().with_variant(postgresql.JSONB(), "postgresql")),
    )
    op.add_column("agent_switch", sa.Column("scanner_stopped_at", sa.DateTime(timezone=True)))
    op.add_column("agent_switch", sa.Column("scanner_stopped", sa.Integer()))
    # Wcześniejsze użycia kill switcha: data zmiany jest najlepszym przybliżeniem.
    op.execute("UPDATE agent_switch SET killed_at = changed_at WHERE killed")


def downgrade() -> None:
    op.drop_column("agent_switch", "scanner_stopped")
    op.drop_column("agent_switch", "scanner_stopped_at")
    op.drop_column("agent_switch", "effects")
    op.drop_column("agent_switch", "killed_at")
