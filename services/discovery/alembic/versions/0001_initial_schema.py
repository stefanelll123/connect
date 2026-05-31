"""initial_schema — complete Discovery Service database schema.

Revision ID: 0001
Revises:
Create Date: 2026-03-15
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------ #
    # apps                                                                #
    # ------------------------------------------------------------------ #
    op.create_table(
        "apps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("owner", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default="true"
        ),
        sa.UniqueConstraint("name", name="uq_apps_name"),
    )

    # ------------------------------------------------------------------ #
    # services                                                            #
    # ------------------------------------------------------------------ #
    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "app_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("apps.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("service_id", sa.Text(), nullable=False),
        sa.Column("env", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner_did", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "env IN ('dev', 'test', 'prod')", name="ck_services_env"
        ),
        sa.UniqueConstraint(
            "service_id", "env", name="uq_services_service_env"
        ),
    )
    op.create_index(
        "idx_services_service_env",
        "services",
        ["service_id", "env", "is_active"],
    )

    # ------------------------------------------------------------------ #
    # sentinels                                                           #
    # ------------------------------------------------------------------ #
    op.create_table(
        "sentinels",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "service_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("services.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("did", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("env", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "config_version", sa.Integer(), server_default="0", nullable=False
        ),
        sa.CheckConstraint(
            "role IN ('producer', 'consumer')", name="ck_sentinels_role"
        ),
        sa.UniqueConstraint(
            "did", "role", "env", name="uq_sentinels_did_role_env"
        ),
    )
    op.create_index("idx_sentinels_did", "sentinels", ["did"])

    # ------------------------------------------------------------------ #
    # sentinel_instances                                                  #
    # ------------------------------------------------------------------ #
    op.create_table(
        "sentinel_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "sentinel_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinels.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("instance_id", sa.Text(), nullable=False, unique=True),
        sa.Column("base_url", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=True),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'draining', 'offline')",
            name="ck_sentinel_instances_status",
        ),
    )
    op.create_index(
        "idx_sentinel_instances_sentinel_status",
        "sentinel_instances",
        ["sentinel_id", "status"],
    )

    # ------------------------------------------------------------------ #
    # enrollment_tokens                                                   #
    # ------------------------------------------------------------------ #
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("jti", sa.Text(), nullable=False, unique=True),
        sa.Column("service_id", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("env", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=True),
        sa.Column("approved_by", sa.Text(), nullable=True),
        # SHA-256 of the raw JWT token — the raw token is NEVER stored
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("approved_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING', 'APPROVED', 'CONSUMED', 'EXPIRED')",
            name="ck_enrollment_tokens_status",
        ),
    )
    op.create_index("idx_enrollment_jti", "enrollment_tokens", ["jti"])
    op.create_index(
        "idx_enrollment_status_exp",
        "enrollment_tokens",
        ["status", "expires_at"],
    )

    # ------------------------------------------------------------------ #
    # credentials                                                         #
    # ------------------------------------------------------------------ #
    op.create_table(
        "credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_type", sa.Text(), nullable=False),
        sa.Column("issuer_did", sa.Text(), nullable=False),
        sa.Column("subject_did", sa.Text(), nullable=False),
        sa.Column("audience", sa.Text(), nullable=True),
        sa.Column("env", sa.Text(), nullable=True),
        sa.Column("jti", sa.Text(), unique=True, nullable=True),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("status_list_id", sa.Text(), nullable=True),
        sa.Column("status_list_index", sa.Integer(), nullable=True),
        sa.Column(
            "is_latest", sa.Boolean(), server_default="true", nullable=False
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked', 'expired', 'deprecated')",
            name="ck_credentials_status",
        ),
    )
    op.create_index(
        "idx_credentials_subject_env",
        "credentials",
        ["subject_did", "env", "is_latest"],
    )

    # ------------------------------------------------------------------ #
    # status_lists                                                        #
    # ------------------------------------------------------------------ #
    op.create_table(
        "status_lists",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("status_list_id", sa.Text(), nullable=False, unique=True),
        sa.Column("issuer_did", sa.Text(), nullable=False),
        sa.Column("env", sa.Text(), nullable=False),
        sa.Column("credential_type", sa.Text(), nullable=True),
        sa.Column("current_hash", sa.Text(), nullable=False),
        sa.Column("bitstring_url", sa.Text(), nullable=True),
        sa.Column("published_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("anchor_tx_hash", sa.Text(), nullable=True),
        sa.Column("anchor_block", sa.BigInteger(), nullable=True),
        sa.Column(
            "anchor_pending", sa.Boolean(), server_default="true", nullable=False
        ),
    )
    op.create_index(
        "idx_status_lists_id_env", "status_lists", ["status_list_id", "env"]
    )

    # ------------------------------------------------------------------ #
    # audit_events  — APPEND-ONLY                                        #
    # ------------------------------------------------------------------ #
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", sa.Text(), unique=True, nullable=True),
        sa.Column(
            "ts",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("prev_hash", sa.Text(), nullable=True),
        sa.Column("event_hash", sa.Text(), nullable=False),
    )
    # Descending index for efficient time-ordered reads
    op.execute("CREATE INDEX idx_audit_ts ON audit_events (ts DESC)")
    op.execute(
        "CREATE INDEX idx_audit_actor ON audit_events (actor_id, action, ts DESC)"
    )

    # ------------------------------------------------------------------ #
    # config_bundles                                                      #
    # ------------------------------------------------------------------ #
    op.create_table(
        "config_bundles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "sentinel_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("sentinels.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("bundle_hash", sa.Text(), nullable=True),
        sa.Column("signed_bundle_jws", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "is_current", sa.Boolean(), server_default="true", nullable=False
        ),
    )
    op.create_index(
        "idx_config_bundles_sentinel_current",
        "config_bundles",
        ["sentinel_id", "is_current"],
    )


def downgrade() -> None:
    op.drop_index("idx_config_bundles_sentinel_current", table_name="config_bundles")
    op.drop_table("config_bundles")

    op.execute("DROP INDEX IF EXISTS idx_audit_actor")
    op.execute("DROP INDEX IF EXISTS idx_audit_ts")
    op.drop_table("audit_events")

    op.drop_index("idx_status_lists_id_env", table_name="status_lists")
    op.drop_table("status_lists")

    op.drop_index("idx_credentials_subject_env", table_name="credentials")
    op.drop_table("credentials")

    op.drop_index("idx_enrollment_status_exp", table_name="enrollment_tokens")
    op.drop_index("idx_enrollment_jti", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")

    op.drop_index(
        "idx_sentinel_instances_sentinel_status", table_name="sentinel_instances"
    )
    op.drop_table("sentinel_instances")

    op.drop_index("idx_sentinels_did", table_name="sentinels")
    op.drop_table("sentinels")

    op.drop_index("idx_services_service_env", table_name="services")
    op.drop_table("services")

    op.drop_table("apps")
