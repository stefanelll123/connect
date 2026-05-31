"""SentinelIdentityCredential Pydantic v2 model.

JWT claims layout::

    {
        "iss": "<Discovery DID>",
        "sub": "<Sentinel DID>",
        "nbf": <Unix timestamp>,
        "exp": <Unix timestamp>,          # max nbf + 365 days
        "jti": "urn:uuid:<uuid4>",
        "vc": {
            "type": ["VerifiableCredential", "SentinelIdentityCredential"],
            "credentialSubject": { ... },
            "credentialStatus":  { ... }
        }
    }
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

from common.vc_schemas.base import (
    MAX_LIFETIME_SENTINEL_IDENTITY,
    ENV_TYPE,
    ROLE_TYPE,
    CredentialStatus,
)

_JTI_PATTERN = (
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class SentinelIdentitySubject(BaseModel):
    """``credentialSubject`` for a SentinelIdentityCredential."""

    model_config = {"frozen": True}

    id: str = Field(
        pattern=r"^did:",
        max_length=512,
        description="Sentinel DID — must be a did:key URI.",
    )
    role: ROLE_TYPE = Field(
        description="Whether this Sentinel is a PRODUCER or CONSUMER.",
    )
    service_id: str = Field(
        pattern=r"^[a-z0-9_-]{1,128}$",
        description="Identifier of the service this Sentinel represents.",
    )
    env: ENV_TYPE = Field(
        description="Deployment environment.",
    )
    instance_count_hint: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Informational maximum expected instance count (non-binding).",
    )


class SentinelIdentityVCClaim(BaseModel):
    """The ``vc`` nested claim object for a SentinelIdentityCredential."""

    model_config = {"frozen": True}

    type: List[str] = Field(
        description="Must contain 'VerifiableCredential' and 'SentinelIdentityCredential'.",
    )
    credentialSubject: SentinelIdentitySubject
    credentialStatus: CredentialStatus

    @model_validator(mode="after")
    def check_vc_types(self) -> "SentinelIdentityVCClaim":
        required = {"VerifiableCredential", "SentinelIdentityCredential"}
        if not required.issubset(set(self.type)):
            raise ValueError(
                f"vc.type must include {sorted(required)}, got {self.type}"
            )
        return self


class SentinelIdentityCredential(BaseModel):
    """Full JWT claim set for a SentinelIdentityCredential.

    Represents the decoded (verified) payload of a JWT-VC.
    Lifetime constraint: ``exp - nbf`` must not exceed 365 days.
    """

    model_config = {"frozen": True}

    iss: str = Field(pattern=r"^did:", max_length=512, description="Issuer DID.")
    sub: str = Field(pattern=r"^did:", max_length=512, description="Subject (Sentinel) DID.")
    nbf: int = Field(ge=0, description="Not-before timestamp (Unix).")
    exp: int = Field(ge=0, description="Expiry timestamp (Unix).")
    jti: str = Field(pattern=_JTI_PATTERN, description="JWT ID — urn:uuid:<uuid4>.")
    vc: SentinelIdentityVCClaim

    @model_validator(mode="after")
    def check_lifetime(self) -> "SentinelIdentityCredential":
        if self.exp <= self.nbf:
            raise ValueError("exp must be greater than nbf.")
        lifetime = self.exp - self.nbf
        if lifetime > MAX_LIFETIME_SENTINEL_IDENTITY:
            raise ValueError(
                f"SentinelIdentityCredential lifetime {lifetime}s exceeds maximum "
                f"{MAX_LIFETIME_SENTINEL_IDENTITY}s (365 days)."
            )
        return self

    @model_validator(mode="after")
    def check_sub_matches_credential_subject(self) -> "SentinelIdentityCredential":
        if self.sub != self.vc.credentialSubject.id:
            raise ValueError(
                f"JWT sub '{self.sub}' must match vc.credentialSubject.id "
                f"'{self.vc.credentialSubject.id}'."
            )
        return self
