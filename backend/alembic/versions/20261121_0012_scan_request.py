"""Etap 6, moduł 21: prośby menedżera o nowe skanowanie (§25.1)

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-21
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0012'
down_revision: str | None = '0011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('scan_request',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('requested_by', sa.String(length=255), nullable=False),
    sa.Column('scope_kind', sa.String(length=16), nullable=False),
    sa.Column('scope_ref', sa.Uuid(), nullable=True),
    sa.Column('scope_label', sa.String(length=255), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('decided_by', sa.String(length=255), nullable=True),
    sa.Column('decision_reason', sa.Text(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('scan_run_id', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("scope_kind IN ('organization', 'unit', 'device')", name=op.f('ck_scan_request_scope_kind_valid')),
    sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'done', 'failed')", name=op.f('ck_scan_request_status_valid')),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_run.id'], name=op.f('fk_scan_request_scan_run_id_scan_run'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_request'))
    )
    op.create_index(op.f('ix_scan_request_requested_by'), 'scan_request', ['requested_by'], unique=False)
    op.create_index(op.f('ix_scan_request_status'), 'scan_request', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_request_status'), table_name='scan_request')
    op.drop_index(op.f('ix_scan_request_requested_by'), table_name='scan_request')
    op.drop_table('scan_request')
