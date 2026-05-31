"""Add chain_events, service_descriptors, sentinel_lifecycle_events, audit_checkpoints; add sentinels.computed_status.

Revision ID: 0004
Revises: 0003
Create Date: 2026-03-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # chain_events — immutable on-chain event log (TASK-031)             #
    # ------------------------------------------------------------------ #
    op.create_table(
        "chain_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tx_hash", sa.Text(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("event_name", sa.Text(), nullable=False),
        sa.Column("contract", sa.Text(), nullable=False),
        sa.Column("args_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "indexed_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("tx_hash", "event_name", name="uq_chain_events_tx_event"),
    )
    op.create_index("idx_chain_events_block", "chain_events", ["block_number"])
    op.create_index("idx_chain_events_contract", "chain_events", ["contract", "event_name"])

    # ------------------------------------------------------------------ #
    # service_descriptors — signed service endpoint descriptors (TASK-032)
    # ------------------------------------------------------------------ #
    op.create_table(
        "service_descriptors",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("service_id", sa.Text(), nullable=False),
        sa.Column("env", sa.Text(), nullable=False),
        sa.Column("producer_sentinel_did", sa.Text(), nullable=True),
        sa.Column("descriptor_hash", sa.Text(), nullable=True),
        sa.Column("signed_descriptor_jws", sa.Text(), nullable=False),
        sa.Column(
            "valid_until",
            postgresql.TIMESTAMP(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "published_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default="true",
        ),
        sa.Column("anchor_tx_hash", sa.Text(), nullable=True),
        sa.UniqueConstraint("service_id", "env", name="uq_service_descriptors_service_env"),
    )
    op.create_index(
        "idx_service_descriptors_service_env",
        "service_descriptors",
        ["service_id", "env", "is_active"],
    )

    # ------------------------------------------------------------------ #
    # sentinel_lifecycle_events — append-only lifecycle audit (TASK-033) #
    # ------------------------------------------------------------------ #
    op.create_table(
        "sentinel_lifecycle_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "sentinel_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinels.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("old_status", sa.Text(), nullable=True),
        sa.Column("new_status", sa.Text(), nullable=True),
        sa.Column("instance_id", sa.Text(), nullable=True),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column(
            "ts",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_sentinel_lifecycle_events_sentinel",
        "sentinel_lifecycle_events",
        ["sentinel_id", "ts"],
    )

    # ------------------------------------------------------------------ #
    # audit_checkpoints — hourly global audit chain hashes (TASK-034)    #
    # ------------------------------------------------------------------ #
    op.create_table(
        "audit_checkpoints",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("checkpoint_hash", sa.Text(), nullable=False),
        sa.Column("events_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "computed_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("anchor_tx_hash", sa.Text(), nullable=True),
    )

    # ------------------------------------------------------------------ #
    # sentinels — add computed_status column (TASK-033)                  #
    # ------------------------------------------------------------------ #
    op.add_column(
        "sentinels",
        sa.Column("computed_status", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sentinels", "computed_status")
    op.drop_table("audit_checkpoints")
    op.drop_index("idx_sentinel_lifecycle_events_sentinel", table_name="sentinel_lifecycle_events")
    op.drop_table("sentinel_lifecycle_events")
    op.drop_index("idx_service_descriptors_service_env", table_name="service_descriptors")
    op.drop_table("service_descriptors")
    op.drop_index("idx_chain_events_contract", table_name="chain_events")
    op.drop_index("idx_chain_events_block", table_name="chain_events")
    op.drop_table("chain_events")
