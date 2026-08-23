"""Add tenant-scoped report artifact metadata.

Revision ID: 0003_report_artifacts
Revises: 0002_evaluation_runs
Create Date: 2026-08-01
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_report_artifacts"
down_revision = "0002_evaluation_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("format", sa.String(length=32), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name=op.f("ck_report_artifacts_size_non_negative"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["evaluation_runs.id"], name="fk_report_artifacts_run_id_evaluation_runs", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_report_artifacts_tenant_id_tenants", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_report_artifacts"),
        sa.UniqueConstraint("tenant_id", "object_key", name="uq_artifacts_tenant_key"),
    )
    op.create_index("ix_artifacts_expiry", "report_artifacts", ["expires_at", "deleted_at"], unique=False)
    op.create_index("ix_artifacts_tenant_run", "report_artifacts", ["tenant_id", "run_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_artifacts_tenant_run", table_name="report_artifacts")
    op.drop_index("ix_artifacts_expiry", table_name="report_artifacts")
    op.drop_table("report_artifacts")
