"""Enrollment API — triggered from the local sentinel UI."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/enrollment", tags=["enrollment"])


class EnrollRequest(BaseModel):
    enrollment_token: str


@router.get("/status")
async def enrollment_status(request: Request) -> dict:
    """Return current enrollment state."""
    ds_client = getattr(request.app.state, "ds_client", None)
    sentinel_id = ""
    enrolled = False
    if ds_client is not None:
        sentinel_id = getattr(ds_client, "sentinel_id", "") or ""
        enrolled = bool(sentinel_id)
    return {"enrolled": enrolled, "sentinel_id": sentinel_id}


@router.post("/enroll")
async def enroll(body: EnrollRequest, request: Request) -> dict:
    """Trigger onboarding with the supplied enrollment token."""
    ds_client = getattr(request.app.state, "ds_client", None)
    if ds_client is None:
        raise HTTPException(status_code=503, detail="Discovery client not initialised")

    token = body.enrollment_token.strip()
    if not token:
        raise HTTPException(status_code=422, detail="enrollment_token is required")

    try:
        bundle = await ds_client.onboard(token)
    except Exception as exc:
        logger.error("Enrollment via UI failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "enrolled": True,
        "sentinel_id": bundle.sentinel_id,
    }
