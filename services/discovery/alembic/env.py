"""Alembic env.py — async migration runner for the Discovery Service.

The DATABASE_URL environment variable overrides the sqlalchemy.url from
alembic.ini.  This env var must be set before running ``alembic upgrade head``.

Usage:
    DATABASE_URL=postgresql+asyncpg://user:pass@host/db alembic upgrade head
"""
from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

# Make the discovery package importable when running migrations directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import Base + all models so Alembic autogenerate detects the full schema
from discovery.db.base import Base
import discovery.db.models  # noqa: F401 — registers all ORM classes with Base.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    """Prefer DATABASE_URL env var; fall back to alembic.ini entry."""
    return os.environ.get(
        "DATABASE_URL",
        config.get_main_option("sqlalchemy.url", ""),
    )


# ---------------------------------------------------------------------------
# Offline migrations (no live DB connection — generates SQL script)
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migrations (live DB connection via asyncpg)
# ---------------------------------------------------------------------------

def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _get_url()

    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
