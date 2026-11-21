"""Etap 6: model organizacji (ARCHITECTURE §7.1, #18)

- działy, lokalizacje, segmenty sieci, osoby (z numerem pseudonimu), przypisania urządzeń do
  osób, źródła inwentarza (z nich wynika reguła shadow IT) i dzienna metryka pokrycia,
- `asset`: powiązania z działem, lokalizacją i segmentem, `in_cmdb`, `confirmed`, nowe typy.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_TYPES = "type IN ('host', 'domain', 'ip', 'service', 'application')"
NEW_TYPES = (
    "type IN ('host', 'domain', 'ip', 'service', 'application', 'workstation', 'laptop', "
    "'server', 'network', 'printer', 'iot', 'cloud', 'ai_system')"
)


def upgrade() -> None:
    op.create_table(
        "coverage_snapshot",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("assets_total", sa.Integer(), nullable=False),
        sa.Column("with_owner", sa.Integer(), nullable=False),
        sa.Column("scanned_recently", sa.Integer(), nullable=False),
        sa.Column("known_version", sa.Integer(), nullable=False),
        sa.Column("unknown_devices", sa.Integer(), nullable=False),
        sa.Column("open_findings", sa.Integer(), nullable=False),
        sa.Column("critical_findings", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_coverage_snapshot")),
        sa.UniqueConstraint("day", name=op.f("uq_coverage_snapshot_day")),
    )
    op.create_table(
        "location",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("address", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_location")),
        sa.UniqueConstraint("external_id", name=op.f("uq_location_external_id")),
    )
    op.create_table(
        "org_unit",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["org_unit.id"],
            name=op.f("fk_org_unit_parent_id_org_unit"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_org_unit")),
        sa.UniqueConstraint("external_id", name=op.f("uq_org_unit_external_id")),
    )
    op.create_index(op.f("ix_org_unit_parent_id"), "org_unit", ["parent_id"], unique=False)
    op.create_table(
        "network_segment",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("location_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["location.id"],
            name=op.f("fk_network_segment_location_id_location"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_segment")),
        sa.UniqueConstraint("cidr", name=op.f("uq_network_segment_cidr")),
    )
    op.create_index(
        op.f("ix_network_segment_location_id"), "network_segment", ["location_id"], unique=False
    )
    op.create_table(
        "person",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("job_title", sa.String(length=255), nullable=True),
        sa.Column("org_unit_id", sa.Uuid(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("pseudonym_no", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("left_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source IN ('ad', 'entra', 'mdm', 'import')", name=op.f("ck_person_source_valid")
        ),
        sa.ForeignKeyConstraint(
            ["org_unit_id"],
            ["org_unit.id"],
            name=op.f("fk_person_org_unit_id_org_unit"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_person")),
        sa.UniqueConstraint("pseudonym_no", name=op.f("uq_person_pseudonym_no")),
        sa.UniqueConstraint("source", "external_id", name=op.f("uq_person_source_external_id")),
    )
    op.create_index(op.f("ix_person_org_unit_id"), "person", ["org_unit_id"], unique=False)
    op.create_table(
        "asset_assignment",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("person_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=8), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=True),
        sa.Column("valid_to", sa.Date(), nullable=True),
        sa.CheckConstraint(
            "role IN ('user', 'owner')", name=op.f("ck_asset_assignment_role_valid")
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["asset.id"],
            name=op.f("fk_asset_assignment_asset_id_asset"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["person_id"],
            ["person.id"],
            name=op.f("fk_asset_assignment_person_id_person"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_assignment")),
        sa.UniqueConstraint(
            "asset_id",
            "person_id",
            "role",
            name=op.f("uq_asset_assignment_asset_id_person_id_role"),
        ),
    )
    op.create_index(
        op.f("ix_asset_assignment_asset_id"), "asset_assignment", ["asset_id"], unique=False
    )
    op.create_index(
        op.f("ix_asset_assignment_person_id"), "asset_assignment", ["person_id"], unique=False
    )
    op.create_table(
        "asset_source",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source IN ('scan', 'csv', 'ad', 'entra', 'mdm', 'cmdb', 'dhcp', 'dns', 'cloud')",
            name=op.f("ck_asset_source_source_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["asset.id"],
            name=op.f("fk_asset_source_asset_id_asset"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_source")),
        sa.UniqueConstraint("asset_id", "source", name=op.f("uq_asset_source_asset_id_source")),
    )
    op.create_index(op.f("ix_asset_source_asset_id"), "asset_source", ["asset_id"], unique=False)
    op.add_column("asset", sa.Column("org_unit_id", sa.Uuid(), nullable=True))
    op.add_column("asset", sa.Column("location_id", sa.Uuid(), nullable=True))
    op.add_column("asset", sa.Column("segment_id", sa.Uuid(), nullable=True))
    op.add_column(
        "asset", sa.Column("in_cmdb", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column(
        "asset", sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.create_index(op.f("ix_asset_location_id"), "asset", ["location_id"], unique=False)
    op.create_index(op.f("ix_asset_org_unit_id"), "asset", ["org_unit_id"], unique=False)
    op.create_index(op.f("ix_asset_segment_id"), "asset", ["segment_id"], unique=False)
    op.create_foreign_key(
        op.f("fk_asset_location_id_location"),
        "asset",
        "location",
        ["location_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_asset_segment_id_network_segment"),
        "asset",
        "network_segment",
        ["segment_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_asset_org_unit_id_org_unit"),
        "asset",
        "org_unit",
        ["org_unit_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_constraint(op.f("ck_asset_type_valid"), "asset", type_="check")
    op.create_check_constraint(op.f("ck_asset_type_valid"), "asset", NEW_TYPES)


def downgrade() -> None:
    op.execute(
        "DELETE FROM asset WHERE type NOT IN ('host', 'domain', 'ip', 'service', 'application')"
    )
    op.drop_constraint(op.f("ck_asset_type_valid"), "asset", type_="check")
    op.create_check_constraint(op.f("ck_asset_type_valid"), "asset", OLD_TYPES)
    op.drop_constraint(op.f("fk_asset_org_unit_id_org_unit"), "asset", type_="foreignkey")
    op.drop_constraint(op.f("fk_asset_segment_id_network_segment"), "asset", type_="foreignkey")
    op.drop_constraint(op.f("fk_asset_location_id_location"), "asset", type_="foreignkey")
    op.drop_index(op.f("ix_asset_segment_id"), table_name="asset")
    op.drop_index(op.f("ix_asset_org_unit_id"), table_name="asset")
    op.drop_index(op.f("ix_asset_location_id"), table_name="asset")
    op.drop_column("asset", "confirmed")
    op.drop_column("asset", "in_cmdb")
    op.drop_column("asset", "segment_id")
    op.drop_column("asset", "location_id")
    op.drop_column("asset", "org_unit_id")
    op.drop_index(op.f("ix_asset_source_asset_id"), table_name="asset_source")
    op.drop_table("asset_source")
    op.drop_index(op.f("ix_asset_assignment_person_id"), table_name="asset_assignment")
    op.drop_index(op.f("ix_asset_assignment_asset_id"), table_name="asset_assignment")
    op.drop_table("asset_assignment")
    op.drop_index(op.f("ix_person_org_unit_id"), table_name="person")
    op.drop_table("person")
    op.drop_index(op.f("ix_network_segment_location_id"), table_name="network_segment")
    op.drop_table("network_segment")
    op.drop_index(op.f("ix_org_unit_parent_id"), table_name="org_unit")
    op.drop_table("org_unit")
    op.drop_table("location")
    op.drop_table("coverage_snapshot")
