"""Add bitstring/dirty/top_index to status_lists; deprecated_until/encrypted_payload to credentials.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-15
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # status_lists — add bitstring storage and management columns         #
    # ------------------------------------------------------------------ #
    op.add_column(
        "status_lists",
        sa.Column("bitstring", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "status_lists",
        sa.Column("top_index", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "status_lists",
        sa.Column("max_size", sa.Integer(), nullable=False, server_default="131072"),
    )
    op.add_column(
        "status_lists",
        sa.Column("dirty", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "status_lists",
        sa.Column("is_frozen", sa.Boolean(), nullable=False, server_default="false"),
    )
    # Make current_hash nullable (it was NOT NULL before but we populate it lazily)
    op.alter_column("status_lists", "current_hash", nullable=True)

    op.create_index(
        "idx_status_lists_bucket",
        "status_lists",
        ["issuer_did", "env", "credential_type", "is_frozen"],
    )

    # ------------------------------------------------------------------ #
    # credentials — rotation grace period and optional encrypted payload  #
    # ------------------------------------------------------------------ #
    op.add_column(
        "credentials",
        sa.Column(
            "deprecated_until",
            postgresql.TIMESTAMP(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "credentials",
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=True),
    )

    # ------------------------------------------------------------------ #
    # config_bundles — make bundle_hash optional-safe (already nullable)  #
    # No schema changes needed — model already correct.                   #
    # ------------------------------------------------------------------ #


def downgrade() -> None:
    op.drop_column("credentials", "encrypted_payload")
    op.drop_column("credentials", "deprecated_until")

    op.drop_index("idx_status_lists_bucket", table_name="status_lists")
    op.drop_column("status_lists", "is_frozen")
    op.drop_column("status_lists", "dirty")
    op.drop_column("status_lists", "max_size")
    op.drop_column("status_lists", "top_index")
    op.drop_column("status_lists", "bitstring")
    op.alter_column("status_lists", "current_hash", nullable=False)
