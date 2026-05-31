"""Add revoked_at to credentials table.

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import TIMESTAMP

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "credentials",
        sa.Column(
            "revoked_at",
            TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("credentials", "revoked_at")
