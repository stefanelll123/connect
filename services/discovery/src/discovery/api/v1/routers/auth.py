"""Auth endpoints — dev-token issuance (dev/local_jwt mode only).

In production this prefix returns 404 for all paths.
"""
from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Auth"])


class DevTokenRequest(BaseModel):
    sub: str
    roles: list[str]
    actor_type: Literal["ADMIN", "BREAK_GLASS"] = "ADMIN"
    email: str = ""


class DevTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


@router.post("/dev-token", response_model=DevTokenResponse, status_code=200)
async def issue_dev_token(body: DevTokenRequest, request: Request) -> DevTokenResponse:
    """Issue a short-lived HS256 JWT.

    Only available when ``ENV=dev`` AND ``AUTH_MODE=local_jwt``.
    Returns 404 in test or prod environments.
    """
    settings = request.app.state.settings

    if settings.env != "dev" or settings.auth_mode != "local_jwt":
        raise HTTPException(
            status_code=404,
            detail={"code": "DEV_ONLY_ENDPOINT", "message": "Endpoint not available in this environment"},
        )

    from discovery.auth.local_jwt import issue_dev_token as _issue

    token = _issue(
        sub=body.sub,
        roles=body.roles,
        secret=settings.local_jwt_secret.get_secret_value(),
        ttl_seconds=settings.auth_token_ttl_seconds,
        actor_type=body.actor_type,
        email=body.email,
    )

    # Break-glass access must leave an unmissable log entry.
    if body.actor_type == "BREAK_GLASS":
        logger.warning(
            "BREAK_GLASS dev-token issued for sub=%r — rotate credentials after use.",
            body.sub,
        )

    return DevTokenResponse(
        access_token=token,
        expires_in=settings.auth_token_ttl_seconds,
    )
