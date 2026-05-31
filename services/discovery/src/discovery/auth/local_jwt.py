"""Local JWT helpers for dev mode.

SECURITY: This module MUST NOT be used in env=prod or env=test.
The startup validator in DiscoverySettings enforces this.
"""
from __future__ import annotations

import time
from typing import Any

import jwt  # PyJWT

from discovery.auth.models import CurrentUser


def issue_dev_token(
    sub: str,
    roles: list[str],
    secret: str,
    ttl_seconds: int = 900,
    *,
    actor_type: str = "ADMIN",
    email: str = "",
) -> str:
    """Sign and return a short-lived HS256 JWT for dev/test environments."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": sub,
        "roles": roles,
        "actor_type": actor_type,
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": "discovery-local",
    }
    if email:
        payload["email"] = email
    return jwt.encode(payload, secret, algorithm="HS256")


def validate_local_token(raw_token: str, secret: str) -> CurrentUser:
    """Validate a locally-issued HS256 JWT and return the CurrentUser.

    Raises:
        ValueError: with code "TOKEN_EXPIRED" or "TOKEN_INVALID".
    """
    try:
        payload = jwt.decode(
            raw_token,
            secret,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError("TOKEN_EXPIRED") from exc
    except jwt.InvalidTokenError as exc:
        raise ValueError("TOKEN_INVALID") from exc

    return CurrentUser(
        sub=payload["sub"],
        roles=payload.get("roles", []),
        email=payload.get("email", ""),
        raw_token=raw_token,
        actor_type=payload.get("actor_type", "ADMIN"),
    )
