"""Etap 5: sygnały bez CPE (KEV podaje producenta i produkt, NVD jeszcze nie podał wersji)

- `signal_match`: dopasowanie produktu z KEV do oprogramowania z inwentarza po nazwie.
  Zawsze czeka na decyzję człowieka; finding (typ `signal`) powstaje dopiero po akceptacji.
- `finding.type`: nowy typ `signal`.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


OLD_TYPES = "type IN ('cve', 'misconfig', 'compliance', 'eol', 'exposure')"
NEW_TYPES = "type IN ('cve', 'misconfig', 'compliance', 'eol', 'exposure', 'signal')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_finding_type_valid"), "finding", type_="check")
    op.create_check_constraint(op.f("ck_finding_type_valid"), "finding", NEW_TYPES)
    op.create_table(
        "signal_match",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("software_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("method", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=False),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finding_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["finding.id"],
            name=op.f("fk_signal_match_finding_id_finding"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["software_id"],
            ["software.id"],
            name=op.f("fk_signal_match_software_id_software"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerability.id"],
            name=op.f("fk_signal_match_vulnerability_id_vulnerability"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_signal_match")),
        sa.UniqueConstraint(
            "vulnerability_id",
            "software_id",
            name=op.f("uq_signal_match_vulnerability_id_software_id"),
        ),
    )
    op.create_index(op.f("ix_signal_match_decision"), "signal_match", ["decision"], unique=False)
    op.create_index(
        op.f("ix_signal_match_software_id"), "signal_match", ["software_id"], unique=False
    )
    op.create_index(
        op.f("ix_signal_match_vulnerability_id"), "signal_match", ["vulnerability_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_signal_match_vulnerability_id"), table_name="signal_match")
    op.drop_index(op.f("ix_signal_match_software_id"), table_name="signal_match")
    op.drop_index(op.f("ix_signal_match_decision"), table_name="signal_match")
    op.drop_table("signal_match")
    op.execute("DELETE FROM finding WHERE type = 'signal'")
    op.drop_constraint(op.f("ck_finding_type_valid"), "finding", type_="check")
    op.create_check_constraint(op.f("ck_finding_type_valid"), "finding", OLD_TYPES)
