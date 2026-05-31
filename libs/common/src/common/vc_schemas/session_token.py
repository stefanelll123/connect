"""SessionTokenCredential Pydantic v2 model.

Represents a short-lived (≤ 15 min) JWT issued by a *producer* sentinel to a
*consumer* sentinel after a successful SD-JWT + KB-JWT session exchange.  The
token is used as a ``Bearer`` credential for subsequent proxied requests within
the session window, avoiding repeated SD-JWT presentation overhead.

JWT claims layout::

    {
        "iss": "<Producer sentinel DID>",
        "sub": "<Consumer sentinel DID>",
        "aud": "<Producer sentinel DID>",   # same as iss
        "iat": <Unix timestamp>,
        "exp": <Unix timestamp>,            # iat + session_token_ttl (max 900 s)
        "jti": "urn:uuid:<uuid4>",
        "service_id": "<service identifier>",
        "env": "dev | test | prod",
        "scope": [ { ScopeEntry } ... ]     # copied from AccessGrantCredential
    }

Header::

    { "alg": "EdDSA", "typ": "session+jwt", "kid": "<producer DID>#<fragment>" }
"""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field, model_validator

from common.vc_schemas.base import ENV_TYPE
from common.vc_schemas.access_grant import ScopeEntry

_JTI_PATTERN = (
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_MAX_SESSION_TTL = 900  # 15 minutes


class SessionTokenCredential(BaseModel):
    """Claims model for a producer-issued session token JWT."""

    model_config = {"frozen": True}

    iss: str = Field(min_length=1, description="Producer sentinel DID (issuer).")
    sub: str = Field(min_length=1, description="Consumer sentinel DID (subject).")
    aud: str = Field(min_length=1, description="Producer sentinel DID (audience = iss).")
    iat: int = Field(description="Issued-at Unix timestamp.")
    exp: int = Field(description="Expiry Unix timestamp (iat + ≤900 s).")
    jti: str = Field(pattern=_JTI_PATTERN, description="Unique token identifier.")
    service_id: str = Field(
        pattern=r"^[a-z0-9_-]{1,128}$",
        description="Service this session is scoped to.",
    )
    env: ENV_TYPE = Field(description="Deployment environment.")
    scope: List[ScopeEntry] = Field(
        min_length=1,
        description="Access scopes copied from the backing AccessGrantCredential.",
    )

    @model_validator(mode="after")
    def check_exp_after_iat(self) -> "SessionTokenCredential":
        if self.exp <= self.iat:
            raise ValueError("exp must be greater than iat")
        return self

    @model_validator(mode="after")
    def check_max_ttl(self) -> "SessionTokenCredential":
        if (self.exp - self.iat) > _MAX_SESSION_TTL:
            raise ValueError(
                f"Session token TTL must not exceed {_MAX_SESSION_TTL} seconds "
                f"(got {self.exp - self.iat} s)."
            )
        return self

    @model_validator(mode="after")
    def check_aud_equals_iss(self) -> "SessionTokenCredential":
        if self.aud != self.iss:
            raise ValueError("aud must equal iss for session tokens (self-issued audience)")
        return self
