"""Record the authenticated submitter of each evaluation run.

Revision ID: 0005_run_created_by
Revises: 0004_api_keys
Create Date: 2026-09-29
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_run_created_by"
down_revision = "0004_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable: rows created before this revision have no trustworthy submitter.
    with op.batch_alter_table("evaluation_runs") as batch:
        batch.add_column(sa.Column("created_by", sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("evaluation_runs") as batch:
        batch.drop_column("created_by")
