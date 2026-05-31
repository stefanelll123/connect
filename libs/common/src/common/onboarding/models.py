"""Request, response, and bundle Pydantic models for the onboarding protocol."""

from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class OnboardInitiateRequest(BaseModel):
    """Phase 1 request body: enrolment token + DID + JWK."""

    enrollment_token: str = Field(
        description="Compact JWS enrollment token issued by Discovery.",
        min_length=1,
    )
    did: str = Field(
        pattern=r"^did:key:z6Mk",
        max_length=512,
        description="Sentinel DID — must be a did:key Ed25519 DID.",
    )
    did_public_key_jwk: dict = Field(  # type: ignore[type-arg]
        description="Public key JWK: kty=OKP, crv=Ed25519, no 'd' field.",
    )


class ChallengeResponse(BaseModel):
    """Phase 1 response: one-time challenge for PoP proof."""

    challenge: str = Field(description="base64url-encoded 32-byte server challenge.")
    expires_in: int = Field(description="Seconds until the challenge expires.", ge=1, le=300)
    correlation_id: str = Field(description="UUID for request correlation / logging.")


class OnboardCompleteRequest(BaseModel):
    """Phase 2 request body: enrollment token + PoP proof."""

    enrollment_token: str = Field(
        description="Same compact JWS token submitted in Phase 1.",
        min_length=1,
    )
    proof: str = Field(
        description="Compact JWS PoP proof signed by Sentinel's DID key.",
        min_length=1,
    )


class ContractAddresses(BaseModel):
    """On-chain smart contract addresses in the trust anchor set."""

    issuer_registry: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    trust_policy_registry: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    status_registry: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    service_registry: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")


class TrustAnchors(BaseModel):
    """Blockchain network and contract trust anchors returned in the onboarding bundle."""

    chain_network: str = Field(
        description="Network name, e.g. 'sepolia' or 'local'.",
        min_length=1,
        max_length=64,
    )
    chain_id: int = Field(ge=1, description="EVM chain ID.")
    rpc_urls: List[str] = Field(
        min_length=1,
        max_length=3,
        description="JSON-RPC endpoint URLs (at least one, max three).",
    )
    contract_addresses: ContractAddresses


class OnboardingBundle(BaseModel):
    """Full response bundle returned after successful onboarding Phase 2."""

    sentinel_id: str = Field(description="UUID of the sentinel record.")
    did: str = Field(pattern=r"^did:", max_length=512)
    role: str = Field(description="'PRODUCER' or 'CONSUMER'.")
    env: str = Field(description="'dev', 'test', or 'prod'.")
    service_id: str = Field(pattern=r"^[a-z0-9_-]{1,128}$")
    config_version: int = Field(ge=1)
    bundle: Optional[dict] = Field(  # type: ignore[type-arg]
        default=None,
        description="Signed config bundle (see TASK-027); null if not yet available.",
    )
    initial_credentials: List[str] = Field(
        default_factory=list,
        description="Array of compact JWT-VC strings.",
    )
    trust_anchors: TrustAnchors


class OnboardingError(BaseModel):
    """Standard error response for onboarding API endpoints."""

    error: str = Field(description="Machine-readable error code.")
    message: str = Field(description="Human-readable description (non-sensitive).")
    correlation_id: str = Field(description="UUID for request correlation.")
