"""stage 2 matching and feed columns

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-16 18:45:36.027744
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('cpe_product',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('vendor', sa.String(length=255), nullable=False),
    sa.Column('product', sa.String(length=255), nullable=False),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cpe_product')),
    sa.UniqueConstraint('vendor', 'product', name=op.f('uq_cpe_product_vendor_product'))
    )
    op.add_column('match_candidate', sa.Column('reason', sa.Text(), server_default='', nullable=False))
    op.add_column('software', sa.Column('port', sa.Integer(), nullable=True))
    op.add_column('software', sa.Column('protocol', sa.String(length=8), nullable=True))
    op.add_column('software', sa.Column('match_method', sa.String(length=20), nullable=True))
    op.drop_constraint(op.f('uq_software_asset_id_vendor_product_version_source'), 'software', type_='unique')
    op.create_unique_constraint(op.f('uq_software_asset_id_product_version_port_source'), 'software', ['asset_id', 'product', 'version', 'port', 'source'])
    op.add_column('vulnerability', sa.Column('kev_date_added', sa.Date(), nullable=True))
    op.add_column('vulnerability', sa.Column('kev_vendor_project', sa.String(length=255), nullable=True))
    op.add_column('vulnerability', sa.Column('kev_product', sa.String(length=255), nullable=True))
    op.add_column('vulnerability', sa.Column('kev_required_action', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('first_ingested', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_index(op.f('ix_vulnerability_first_ingested'), 'vulnerability', ['first_ingested'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_vulnerability_first_ingested'), table_name='vulnerability')
    op.drop_column('vulnerability', 'first_ingested')
    op.drop_column('vulnerability', 'kev_required_action')
    op.drop_column('vulnerability', 'kev_product')
    op.drop_column('vulnerability', 'kev_vendor_project')
    op.drop_column('vulnerability', 'kev_date_added')
    op.drop_constraint(op.f('uq_software_asset_id_product_version_port_source'), 'software', type_='unique')
    op.create_unique_constraint(op.f('uq_software_asset_id_vendor_product_version_source'), 'software', ['asset_id', 'vendor', 'product', 'version', 'source'], postgresql_nulls_not_distinct=False)
    op.drop_column('software', 'match_method')
    op.drop_column('software', 'protocol')
    op.drop_column('software', 'port')
    op.drop_column('match_candidate', 'reason')
    op.drop_table('cpe_product')
