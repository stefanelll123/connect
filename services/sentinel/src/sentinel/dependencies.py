"""Dependency injection helpers for the Sentinel Node (TASK-037).

All dependencies read from ``request.app.state`` which is populated during
the lifespan startup in ``app.py``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from fastapi import Request

if TYPE_CHECKING:
    from sentinel.config import SentinelSettings
    from sentinel.wallet.credential_store import CredentialStore
    from sentinel.wallet.status_cache import StatusCache


def get_settings(request: Request) -> "SentinelSettings":
    return request.app.state.settings


def get_http_client(request: Request):
    """Return the shared HTTPX async client."""
    client = getattr(request.app.state, "http_client", None)
    if client is None:
        raise RuntimeError("HTTP client not initialised")
    return client


def get_credential_store(request: Request) -> Optional["CredentialStore"]:
    return getattr(request.app.state, "credential_store", None)


def get_status_cache(request: Request) -> Optional["StatusCache"]:
    return getattr(request.app.state, "status_cache", None)
