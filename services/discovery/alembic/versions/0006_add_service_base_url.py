"""Add base_url column to services table.

Revision ID: 0006
Revises: 0005
Create Date: 2026-03-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "services",
        sa.Column("base_url", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("services", "base_url")
