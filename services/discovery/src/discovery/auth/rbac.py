"""RBAC dependency factory for FastAPI.

Usage (in router)::

    @router.post("/", dependencies=[Depends(require_roles("operator"))])
    async def create_resource(...):
        ...

Or to access current user in handler::

    @router.post("/")
    async def create_resource(
        current_user: CurrentUser = Depends(require_roles("operator")),
    ):
        ...

Multiple roles means ANY of those roles is acceptable::

    Depends(require_roles("operator", "security-admin"))
"""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import Depends, HTTPException, Request

from discovery.auth.models import CurrentUser

logger = logging.getLogger(__name__)


async def get_current_user(request: Request) -> CurrentUser:
    """Extract, validate, and return the CurrentUser from the Bearer token.

    Raises:
        HTTPException 401: token absent or invalid.
    """
    settings = request.app.state.settings

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"code": "TOKEN_MISSING", "message": "Authorization header absent"},
        )

    raw_token = auth_header[7:]

    try:
        if settings.auth_mode == "local_jwt":
            from discovery.auth.local_jwt import validate_local_token

            user = validate_local_token(
                raw_token, settings.local_jwt_secret.get_secret_value()
            )
        else:  # oidc
            try:
                from discovery.auth.oidc import validate_oidc_token

                user = await validate_oidc_token(
                    raw_token,
                    settings.oidc_issuer_url,
                    settings.discovery_audience,
                    settings.oidc_jwks_url,
                )
            except ValueError as oidc_exc:
                # Fallback: accept locally-issued sentinel service-account tokens
                # (actor_type="SENTINEL") even when Discovery runs in OIDC mode.
                try:
                    from discovery.auth.local_jwt import validate_local_token

                    candidate = validate_local_token(
                        raw_token, settings.local_jwt_secret.get_secret_value()
                    )
                    if candidate.actor_type != "SENTINEL":
                        raise ValueError("LOCAL_NOT_SENTINEL")
                    user = candidate
                except ValueError:
                    raise oidc_exc  # surface the original OIDC failure
    except ValueError as exc:
        code = str(exc)
        if "TOKEN_EXPIRED" in code:
            raise HTTPException(
                status_code=401,
                detail={"code": "TOKEN_EXPIRED", "message": "JWT exp has passed"},
            )
        raise HTTPException(
            status_code=401,
            detail={
                "code": "TOKEN_INVALID",
                "message": "JWT signature or claims invalid",
            },
        )

    return user


def require_roles(*roles: str) -> Callable:
    """Return a FastAPI dependency that enforces at least one of *roles*.

    Raises:
        HTTPException 401: no valid token.
        HTTPException 403: token present but none of *roles* possessed.
    """

    async def _check_roles(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if not any(r in current_user.roles for r in roles):
            logger.warning(
                "Access denied user=%s roles=%s required_any=%s",
                current_user.sub,
                current_user.roles,
                roles,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "INSUFFICIENT_ROLE",
                    "message": f"Requires one of roles: {list(roles)}",
                },
            )
        return current_user

    return _check_roles
