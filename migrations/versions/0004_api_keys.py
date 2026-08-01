"""Add one-way API key credential storage.

Revision ID: 0004_api_keys
Revises: 0003_report_artifacts
Create Date: 2026-08-01
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_api_keys"
down_revision = "0003_report_artifacts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("salt", sa.String(length=64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_api_keys_tenant_id_tenants", ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
    )
    op.create_index(
        "ix_api_keys_expiry_revoked", "api_keys", ["expires_at", "revoked_at"], unique=False
    )
    op.create_index(
        "ix_api_keys_tenant_expiry", "api_keys", ["tenant_id", "expires_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_api_keys_tenant_expiry", table_name="api_keys")
    op.drop_index("ix_api_keys_expiry_revoked", table_name="api_keys")
    op.drop_table("api_keys")
