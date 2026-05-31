"""Add cancelled_at and constraints columns to enrollment_tokens.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-15
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "enrollment_tokens",
        sa.Column("cancelled_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "enrollment_tokens",
        sa.Column("constraints", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("enrollment_tokens", "constraints")
    op.drop_column("enrollment_tokens", "cancelled_at")
