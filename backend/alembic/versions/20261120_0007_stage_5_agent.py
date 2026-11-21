"""Etap 5: agent AI, poświadczenia JIT, kill switch i test bezpieczeństwa agenta (moduł 19)

- `agent_capability`: wersje zdolności nadawane przez admina (aktywna najwyżej jedna).
- `agent_config_version`: konfiguracja agenta za bramką zmian (aktywna po zaliczonym teście).
- `agent_task`, `agent_step`: polecenie, plan, decyzje walidatora i człowieka, wyniki kroków.
- `credential_lease`: wydane poświadczenia JIT bez sekretów (TTL, odwołanie).
- `agent_switch`: stan kill switcha.
- `agent_test_run`, `agent_test_case_result`: podpisane wyniki testu agenta (zapisuje harness).

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "agent_capability",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("tools", JSON, nullable=False),
        sa.Column("targets", JSON, nullable=False),
        sa.Column("max_level", sa.Integer(), nullable=False),
        sa.Column("windows", JSON, nullable=False),
        sa.Column("max_calls_per_task", sa.Integer(), nullable=False),
        sa.Column("max_calls_per_target", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "max_level BETWEEN 1 AND 3", name=op.f("ck_agent_capability_max_level_range")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_capability")),
        sa.UniqueConstraint("version", name=op.f("uq_agent_capability_version")),
    )
    op.create_index(
        op.f("ix_agent_capability_active"), "agent_capability", ["active"], unique=False
    )
    op.create_table(
        "agent_config_version",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("capability_version", sa.Integer(), nullable=False),
        sa.Column("external_llm", sa.Boolean(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("forced_by", sa.String(length=255), nullable=True),
        sa.Column("force_justification", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('pending_test', 'active', 'forced', 'rejected', 'superseded')",
            name=op.f("ck_agent_config_version_state_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_config_version")),
    )
    op.create_index(
        op.f("ix_agent_config_version_state"), "agent_config_version", ["state"], unique=False
    )
    op.create_table(
        "agent_switch",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("killed", sa.Boolean(), nullable=False),
        sa.Column("changed_by", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_switch")),
    )
    op.create_table(
        "agent_test_run",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("config_version_id", sa.Uuid(), nullable=True),
        sa.Column("suite", sa.String(length=8), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("model_passed", sa.Integer(), nullable=False),
        sa.Column("model_failed", sa.Integer(), nullable=False),
        sa.Column("code_passed", sa.Integer(), nullable=False),
        sa.Column("code_failed", sa.Integer(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=True),
        sa.Column("result_sha256", sa.String(length=64), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "suite IN ('quick', 'full')", name=op.f("ck_agent_test_run_suite_valid")
        ),
        sa.CheckConstraint(
            "trigger IN ('manual', 'config_change', 'nightly')",
            name=op.f("ck_agent_test_run_trigger_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["config_version_id"],
            ["agent_config_version.id"],
            name=op.f("fk_agent_test_run_config_version_id_agent_config_version"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_test_run")),
    )
    op.create_index(
        op.f("ix_agent_test_run_config_version_id"),
        "agent_test_run",
        ["config_version_id"],
        unique=False,
    )
    op.create_table(
        "agent_task",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("capability_version", sa.Integer(), nullable=True),
        sa.Column("config_version_id", sa.Uuid(), nullable=True),
        sa.Column("parent_task_id", sa.Uuid(), nullable=True),
        sa.Column("plan_source", sa.String(length=10), nullable=True),
        sa.Column("plan_model", sa.String(length=128), nullable=True),
        sa.Column("plan_problems", JSON, nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("test_run_id", sa.Uuid(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approval_reason", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("report_id", sa.Uuid(), nullable=True),
        sa.Column("summary", JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "plan_source IS NULL OR plan_source IN ('model', 'template')",
            name=op.f("ck_agent_task_plan_source_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('planning', 'awaiting_approval', 'approved', 'running', 'done', 'failed', 'rejected', 'killed')",
            name=op.f("ck_agent_task_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["config_version_id"],
            ["agent_config_version.id"],
            name=op.f("fk_agent_task_config_version_id_agent_config_version"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["parent_task_id"],
            ["agent_task.id"],
            name=op.f("fk_agent_task_parent_task_id_agent_task"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["report.id"],
            name=op.f("fk_agent_task_report_id_report"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["test_run_id"],
            ["agent_test_run.id"],
            name=op.f("fk_agent_task_test_run_id_agent_test_run"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_task")),
    )
    op.create_index(op.f("ix_agent_task_status"), "agent_task", ["status"], unique=False)
    op.create_table(
        "agent_test_case_result",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("model_resisted", sa.Boolean(), nullable=False),
        sa.Column("code_held", sa.Boolean(), nullable=False),
        sa.Column("verdicts", JSON, nullable=False),
        sa.Column("transcript", JSON, nullable=False),
        sa.Column("attempts", JSON, nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["agent_test_run.id"],
            name=op.f("fk_agent_test_case_result_run_id_agent_test_run"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_test_case_result")),
    )
    op.create_index(
        op.f("ix_agent_test_case_result_run_id"), "agent_test_case_result", ["run_id"], unique=False
    )
    op.create_table(
        "agent_step",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("params", JSON, nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("decision", sa.String(length=64), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("result", JSON, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "source IN ('plan', 'follow_up')", name=op.f("ck_agent_step_source_valid")
        ),
        sa.CheckConstraint(
            "status IN ('planned', 'blocked', 'approved', 'skipped', 'running', 'done', 'failed')",
            name=op.f("ck_agent_step_status_valid"),
        ),
        sa.CheckConstraint("level BETWEEN 1 AND 4", name=op.f("ck_agent_step_level_range")),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["agent_task.id"],
            name=op.f("fk_agent_step_task_id_agent_task"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_step")),
        sa.UniqueConstraint("task_id", "position", name=op.f("uq_agent_step_task_id_position")),
    )
    op.create_index(op.f("ix_agent_step_status"), "agent_step", ["status"], unique=False)
    op.create_index(op.f("ix_agent_step_task_id"), "agent_step", ["task_id"], unique=False)
    op.create_table(
        "credential_lease",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("step_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("principal", sa.String(length=64), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=False),
        sa.Column("lease_id", sa.String(length=255), nullable=True),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("issued_by", sa.String(length=255), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["step_id"],
            ["agent_step.id"],
            name=op.f("fk_credential_lease_step_id_agent_step"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["agent_task.id"],
            name=op.f("fk_credential_lease_task_id_agent_task"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_credential_lease")),
    )
    op.create_index(
        op.f("ix_credential_lease_task_id"), "credential_lease", ["task_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_credential_lease_task_id"), table_name="credential_lease")
    op.drop_table("credential_lease")
    op.drop_index(op.f("ix_agent_step_task_id"), table_name="agent_step")
    op.drop_index(op.f("ix_agent_step_status"), table_name="agent_step")
    op.drop_table("agent_step")
    op.drop_index(op.f("ix_agent_test_case_result_run_id"), table_name="agent_test_case_result")
    op.drop_table("agent_test_case_result")
    op.drop_index(op.f("ix_agent_task_status"), table_name="agent_task")
    op.drop_table("agent_task")
    op.drop_index(op.f("ix_agent_test_run_config_version_id"), table_name="agent_test_run")
    op.drop_table("agent_test_run")
    op.drop_table("agent_switch")
    op.drop_index(op.f("ix_agent_config_version_state"), table_name="agent_config_version")
    op.drop_table("agent_config_version")
    op.drop_index(op.f("ix_agent_capability_active"), table_name="agent_capability")
    op.drop_table("agent_capability")
