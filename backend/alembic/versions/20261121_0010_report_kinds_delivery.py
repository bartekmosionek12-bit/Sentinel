"""Etap 6: nowe rodzaje raportów (digest, raport z testu agenta)

- `report.kind`: `digest` (podsumowanie zbiorcze z powiadomień) i `ai_test`
  („Czy nasz agent AI jest bezpieczny?”, po teście agenta, moduł 19).

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-21
"""

from __future__ import annotations

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

NEW = "kind IN ('assessment', 'zero_day', 'digest', 'ai_test')"
OLD = "kind IN ('assessment', 'zero_day')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_report_kind_valid"), "report", type_="check")
    op.create_check_constraint(op.f("ck_report_kind_valid"), "report", NEW)


def downgrade() -> None:
    op.execute("DELETE FROM report WHERE kind IN ('digest', 'ai_test')")
    op.drop_constraint(op.f("ck_report_kind_valid"), "report", type_="check")
    op.create_check_constraint(op.f("ck_report_kind_valid"), "report", OLD)
