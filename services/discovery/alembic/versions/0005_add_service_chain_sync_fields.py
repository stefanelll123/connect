"""Add chain sync state columns to services table (TASK-031 Step 6).

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "services",
        sa.Column(
            "chain_sync_pending",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.add_column(
        "services",
        sa.Column("chain_tx_hash", sa.Text(), nullable=True),
    )
    op.add_column(
        "services",
        sa.Column(
            "chain_sync_attempts",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "services",
        sa.Column(
            "chain_next_retry_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        "idx_services_chain_sync_pending",
        "services",
        ["chain_sync_pending", "chain_next_retry_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_services_chain_sync_pending", table_name="services")
    op.drop_column("services", "chain_next_retry_at")
    op.drop_column("services", "chain_sync_attempts")
    op.drop_column("services", "chain_tx_hash")
    op.drop_column("services", "chain_sync_pending")
