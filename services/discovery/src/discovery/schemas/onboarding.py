"""Pydantic v2 schemas for sentinel onboarding (TASK-026)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

_DID_PATTERN = r"^did:(key|web):[a-zA-Z0-9._\-:]+$"


class OnboardingProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str  # e.g. "Ed25519Signature2020"
    created: str  # ISO-8601 timestamp
    challenge_nonce: str
    proof_value: str  # multibase-encoded signature


class OnboardingRequest(BaseModel):
    """Combined challenge + proof request body.

    Phase 1 (challenge): omit ``proof`` field.
    Phase 2 (proof):     include ``proof`` field.
    """

    model_config = ConfigDict(extra="forbid")

    enrollment_token: str = Field(..., description="Raw JWT enrollment token")
    did: str = Field(..., pattern=_DID_PATTERN)
    proof: Optional[OnboardingProof] = None


class ChallengeResponse(BaseModel):
    """Returned in Phase 1 when no proof is provided."""

    challenge_nonce: str
    challenge_expires_at: datetime


class ContractAddresses(BaseModel):
    issuer_registry: str
    trust_policy_registry: str
    status_registry: str
    service_registry: str


class ChainInfo(BaseModel):
    network: str
    rpc_urls: list[str]
    contract_addresses: ContractAddresses


class DiscoveryUrls(BaseModel):
    sync_url: str
    credentials_url: str


class RevocationInfo(BaseModel):
    delta_seconds: int = 300


class CredentialBundle(BaseModel):
    sentinel_identity: Optional[str] = None  # JWT-VC (may be None if async)
    credentials_pending: bool = False


class OnboardingBundle(BaseModel):
    """Complete bootstrap bundle returned to the sentinel after onboarding."""

    sentinel_id: uuid.UUID
    did: str
    role: str
    env: str
    config_version: int
    discovery: DiscoveryUrls
    chain: ChainInfo
    revocation: RevocationInfo
    credentials: CredentialBundle
    access_token: str = ""  # Short-lived sentinel service-account JWT
