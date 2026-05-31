"""ServiceBindingCredential Pydantic v2 model.

JWT claims layout::

    {
        "iss": "<Service Owner authority DID>",
        "sub": "<Sentinel DID>",
        "nbf": <Unix timestamp>,
        "exp": <Unix timestamp>,          # max nbf + 90 days for prod
        "jti": "urn:uuid:<uuid4>",
        "vc": {
            "type": ["VerifiableCredential", "ServiceBindingCredential"],
            "credentialSubject": { ... },
            "credentialStatus":  { ... }  # optional for non-prod
        }
    }
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

from common.vc_schemas.base import (
    MAX_LIFETIME_SERVICE_BINDING_PROD,
    ENV_TYPE,
    CredentialStatus,
)

_JTI_PATTERN = (
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ServiceBindingSubject(BaseModel):
    """``credentialSubject`` for a ServiceBindingCredential."""

    model_config = {"frozen": True}

    sentinel_did: str = Field(
        pattern=r"^did:",
        max_length=512,
        description="DID of the Sentinel being bound to this service.",
    )
    service_id: str = Field(
        pattern=r"^[a-z0-9_-]{1,128}$",
        description="Service the Sentinel is authorised to represent.",
    )
    env: ENV_TYPE = Field(description="Deployment environment.")
    valid_endpoint_patterns: Optional[List[str]] = Field(
        default=None,
        max_length=20,
        description="URL glob patterns for allowed endpoints (max 20, each max 512 chars).",
    )

    @model_validator(mode="after")
    def check_endpoint_pattern_lengths(self) -> "ServiceBindingSubject":
        if self.valid_endpoint_patterns:
            for pat in self.valid_endpoint_patterns:
                if len(pat) > 512:
                    raise ValueError(
                        f"Endpoint pattern exceeds 512 characters: {pat[:64]}..."
                    )
        return self


class ServiceBindingVCClaim(BaseModel):
    """The ``vc`` nested claim for a ServiceBindingCredential."""

    model_config = {"frozen": True}

    type: List[str]
    credentialSubject: ServiceBindingSubject
    credentialStatus: Optional[CredentialStatus] = None

    @model_validator(mode="after")
    def check_vc_types(self) -> "ServiceBindingVCClaim":
        required = {"VerifiableCredential", "ServiceBindingCredential"}
        if not required.issubset(set(self.type)):
            raise ValueError(
                f"vc.type must include {sorted(required)}, got {self.type}"
            )
        return self


class ServiceBindingCredential(BaseModel):
    """Full JWT claim set for a ServiceBindingCredential.

    Lifetime constraint: in prod, ``exp - nbf`` must not exceed 90 days.
    ``credentialStatus`` is optional; non-prod deployments may omit it.
    """

    model_config = {"frozen": True}

    iss: str = Field(pattern=r"^did:", max_length=512, description="Issuer DID.")
    sub: str = Field(pattern=r"^did:", max_length=512, description="Subject (Sentinel) DID.")
    nbf: int = Field(ge=0)
    exp: int = Field(ge=0)
    jti: str = Field(pattern=_JTI_PATTERN)
    vc: ServiceBindingVCClaim

    @model_validator(mode="after")
    def check_exp_after_nbf(self) -> "ServiceBindingCredential":
        if self.exp <= self.nbf:
            raise ValueError("exp must be greater than nbf.")
        return self

    @model_validator(mode="after")
    def check_prod_max_lifetime(self) -> "ServiceBindingCredential":
        env = self.vc.credentialSubject.env
        lifetime = self.exp - self.nbf
        if env == "prod" and lifetime > MAX_LIFETIME_SERVICE_BINDING_PROD:
            raise ValueError(
                f"ServiceBindingCredential lifetime {lifetime}s exceeds the 90-day maximum "
                f"({MAX_LIFETIME_SERVICE_BINDING_PROD}s) for prod environment."
            )
        return self

    @model_validator(mode="after")
    def check_sub_matches_sentinel_did(self) -> "ServiceBindingCredential":
        if self.sub != self.vc.credentialSubject.sentinel_did:
            raise ValueError(
                f"JWT sub '{self.sub}' must match vc.credentialSubject.sentinel_did "
                f"'{self.vc.credentialSubject.sentinel_did}'."
            )
        return self
