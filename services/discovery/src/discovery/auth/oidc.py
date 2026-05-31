"""OIDC token validation with JWKS caching.

JWKS is cached in memory for _CACHE_TTL seconds.  On 'kid not found' the
cache is refreshed once — this handles key rotation without constant
refetching.

Supported algorithms: RS256, ES256.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
import jwt  # PyJWT
import jwt.algorithms  # type: ignore[import-untyped]

from discovery.auth.models import CurrentUser

logger = logging.getLogger(__name__)

_CACHE_TTL = 3600.0  # 1 hour
_SUPPORTED_ALGORITHMS = ("RS256", "ES256")

# ---------------------------------------------------------------------------
# Module-level JWKS cache (shared across all requests)
# ---------------------------------------------------------------------------
_jwks_cache: dict[str, Any] = {}  # kid → JWK dict
_cache_fetched_at: float = 0.0
_cache_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    global _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()
    return _cache_lock


async def _do_refresh_jwks(jwks_url: str) -> None:
    """Fetch fresh JWKS from the IdP and populate the module cache."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(jwks_url)
        resp.raise_for_status()
    data = resp.json()
    global _jwks_cache, _cache_fetched_at
    _jwks_cache = {k.get("kid", "default"): k for k in data.get("keys", [])}
    _cache_fetched_at = time.monotonic()
    logger.info("JWKS refreshed: %d keys from %s", len(_jwks_cache), jwks_url)


async def _get_jwks(jwks_url: str) -> dict[str, Any]:
    """Return cached JWKS, refreshing if stale or empty."""
    lock = _get_lock()
    async with lock:
        if time.monotonic() - _cache_fetched_at > _CACHE_TTL or not _jwks_cache:
            await _do_refresh_jwks(jwks_url)
    return dict(_jwks_cache)


def _build_jwks_url(issuer_url: str, jwks_url: str) -> str:
    """Return jwks_url if set, otherwise derive it from issuer_url."""
    if jwks_url:
        return jwks_url
    return f"{issuer_url.rstrip('/')}/protocol/openid-connect/certs"


async def validate_oidc_token(
    raw_token: str,
    issuer_url: str,
    audience: str,
    jwks_url: str = "",
) -> CurrentUser:
    """Validate a Bearer JWT from an OIDC IdP.

    Raises:
        ValueError: "TOKEN_EXPIRED" or "TOKEN_INVALID:<reason>".
    """
    try:
        header = jwt.get_unverified_header(raw_token)
    except jwt.DecodeError as exc:
        raise ValueError("TOKEN_INVALID: malformed header") from exc

    alg = header.get("alg", "")
    if alg not in _SUPPORTED_ALGORITHMS:
        raise ValueError(f"TOKEN_INVALID: unsupported algorithm {alg!r}")

    kid = header.get("kid", "default")
    resolved_jwks_url = _build_jwks_url(issuer_url, jwks_url)

    # 1. Try cached JWKS
    jwks = await _get_jwks(resolved_jwks_url)
    if kid not in jwks:
        # 2. Re-fetch once on key miss (handles rotation)
        lock = _get_lock()
        async with lock:
            await _do_refresh_jwks(resolved_jwks_url)
        jwks = dict(_jwks_cache)
    if kid not in jwks:
        raise ValueError(f"TOKEN_INVALID: unknown key ID {kid!r}")

    key_data = jwks[kid]
    if alg == "RS256":
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
    else:
        public_key = jwt.algorithms.ECAlgorithm.from_jwk(key_data)  # ES256

    try:
        payload = jwt.decode(
            raw_token,
            public_key,
            algorithms=[alg],
            audience=audience,
            issuer=issuer_url,
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError("TOKEN_EXPIRED") from exc
    except jwt.InvalidTokenError as exc:
        raise ValueError(f"TOKEN_INVALID: {exc}") from exc

    return CurrentUser(
        sub=payload["sub"],
        roles=payload.get("roles", []),
        email=payload.get("email", ""),
        raw_token=raw_token,
    )
