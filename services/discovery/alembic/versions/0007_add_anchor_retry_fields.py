"""Add anchor_attempts and anchor_next_retry_at to status_lists.

Revision ID: 0007
Revises: 0006
Create Date: 2026-03-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import TIMESTAMP

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "status_lists",
        sa.Column("anchor_attempts", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "status_lists",
        sa.Column(
            "anchor_next_retry_at",
            TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_status_lists_anchor_pending_retry",
        "status_lists",
        ["anchor_pending", "anchor_next_retry_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_status_lists_anchor_pending_retry", table_name="status_lists")
    op.drop_column("status_lists", "anchor_next_retry_at")
    op.drop_column("status_lists", "anchor_attempts")
