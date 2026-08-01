"""Add durable tenant-scoped evaluation runs and leases.

Revision ID: 0002_evaluation_runs
Revises: 0001_commercial_metadata
Create Date: 2026-08-01
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002_evaluation_runs"
down_revision = "0001_commercial_metadata"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("suite_version", sa.String(length=128), nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("fencing_token", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint("attempt >= 0", name="ck_evaluation_runs_attempt_non_negative"),
        sa.CheckConstraint(
            "fencing_token >= 0", name="ck_evaluation_runs_fencing_non_negative"
        ),
        sa.CheckConstraint("seed >= 0", name="ck_evaluation_runs_seed_non_negative"),
        sa.CheckConstraint("version >= 1", name="ck_evaluation_runs_version_positive"),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_evaluation_runs_project_id_projects", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], name="fk_evaluation_runs_tenant_id_tenants", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evaluation_runs"),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_runs_tenant_idempotency"
        ),
    )
    op.create_index(
        "ix_runs_claim",
        "evaluation_runs",
        ["status", "lease_expires_at", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_runs_tenant_created",
        "evaluation_runs",
        ["tenant_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_runs_tenant_created", table_name="evaluation_runs")
    op.drop_index("ix_runs_claim", table_name="evaluation_runs")
    op.drop_table("evaluation_runs")
