"""AccessGrantCredential and ScopeEntry Pydantic v2 models.

JWT claims layout::

    {
        "iss": "<Producer authority DID or Discovery DID>",
        "sub": "<Consumer Sentinel DID>",
        "aud": "<Producer Service DID>",       # REQUIRED — exact match
        "nbf": <Unix timestamp>,
        "exp": <Unix timestamp>,               # max nbf + 30 days for prod
        "jti": "urn:uuid:<uuid4>",
        "vc": {
            "type": ["VerifiableCredential", "AccessGrantCredential"],
            "credentialSubject": { ... },
            "credentialStatus":  { ... }       # REQUIRED
        }
    }
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, model_validator

from common.vc_schemas.base import (
    MAX_LIFETIME_ACCESS_GRANT_PROD,
    ENV_TYPE,
    HTTP_METHOD_TYPE,
    CredentialStatus,
)

_JTI_PATTERN = (
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ScopeEntry(BaseModel):
    """A single resource + method access rule within an AccessGrantCredential.

    Wildcard rules (security constraints):

    * In prod, ``*`` is allowed in individual path segments.
    * ``**`` (recursive wildcard) requires an explicit ``approval_reference``
      regardless of environment.
    """

    model_config = {"frozen": True}

    service_id: str = Field(
        pattern=r"^[a-z0-9_-]{1,128}$",
        description="Service this scope entry applies to.",
    )
    path_glob: str = Field(
        min_length=1,
        max_length=256,
        description="Path glob, e.g. /api/v1/citizens/*.",
    )
    methods: List[HTTP_METHOD_TYPE] = Field(
        min_length=1,
        description="HTTP methods allowed for this scope entry.",
    )
    attributes: Optional[List[str]] = Field(
        default=None,
        max_length=20,
        description="ABAC attribute constraints (informational).",
    )
    approval_reference: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Security-admin approval reference — required for ** wildcards.",
    )

    @model_validator(mode="after")
    def check_double_wildcard_has_approval(self) -> "ScopeEntry":
        if "**" in self.path_glob and self.approval_reference is None:
            raise ValueError(
                "path_glob containing '**' requires an approval_reference "
                "(security-admin approval is mandatory for recursive wildcards)."
            )
        return self


class AccessGrantSubject(BaseModel):
    """``credentialSubject`` for an AccessGrantCredential."""

    model_config = {"frozen": True}

    id: str = Field(
        pattern=r"^did:",
        max_length=512,
        description="Consumer Sentinel DID.",
    )
    aud: str = Field(
        pattern=r"^did:",
        max_length=512,
        description="Producer Service DID — exact match required.",
    )
    env: ENV_TYPE = Field(description="Deployment environment.")
    scope: List[ScopeEntry] = Field(
        min_length=1,
        max_length=50,
        description="Access scope entries; at least one is required.",
    )
    max_requests_per_minute: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
        description="Rate-limit hint for the consumer (non-binding).",
    )


class AccessGrantVCClaim(BaseModel):
    """The ``vc`` nested claim for an AccessGrantCredential."""

    model_config = {"frozen": True}

    type: List[str]
    credentialSubject: AccessGrantSubject
    credentialStatus: CredentialStatus  # REQUIRED — no status pointer means reject

    @model_validator(mode="after")
    def check_vc_types(self) -> "AccessGrantVCClaim":
        required = {"VerifiableCredential", "AccessGrantCredential"}
        if not required.issubset(set(self.type)):
            raise ValueError(
                f"vc.type must include {sorted(required)}, got {self.type}"
            )
        return self


class AccessGrantCredential(BaseModel):
    """Full JWT claim set for an AccessGrantCredential.

    Lifetime constraint: in prod, ``exp - nbf`` must not exceed 30 days.
    ``credentialStatus`` is mandatory — VCs without a status pointer are rejected.
    """

    model_config = {"frozen": True}

    iss: str = Field(pattern=r"^did:", max_length=512, description="Issuer DID.")
    sub: str = Field(pattern=r"^did:", max_length=512, description="Consumer Sentinel DID.")
    aud: str = Field(pattern=r"^did:", max_length=512, description="Producer Service DID.")
    nbf: int = Field(ge=0)
    exp: int = Field(ge=0)
    jti: str = Field(pattern=_JTI_PATTERN)
    vc: AccessGrantVCClaim

    @model_validator(mode="after")
    def check_exp_after_nbf(self) -> "AccessGrantCredential":
        if self.exp <= self.nbf:
            raise ValueError("exp must be greater than nbf.")
        return self

    @model_validator(mode="after")
    def check_prod_max_lifetime(self) -> "AccessGrantCredential":
        env = self.vc.credentialSubject.env
        lifetime = self.exp - self.nbf
        if env == "prod" and lifetime > MAX_LIFETIME_ACCESS_GRANT_PROD:
            raise ValueError(
                f"AccessGrantCredential lifetime {lifetime}s exceeds the 30-day maximum "
                f"({MAX_LIFETIME_ACCESS_GRANT_PROD}s) for prod environment."
            )
        return self

    @model_validator(mode="after")
    def check_sub_matches_credential_subject(self) -> "AccessGrantCredential":
        if self.sub != self.vc.credentialSubject.id:
            raise ValueError(
                f"JWT sub '{self.sub}' must match vc.credentialSubject.id "
                f"'{self.vc.credentialSubject.id}'."
            )
        return self

    @model_validator(mode="after")
    def check_aud_matches_credential_subject(self) -> "AccessGrantCredential":
        if self.aud != self.vc.credentialSubject.aud:
            raise ValueError(
                f"JWT aud '{self.aud}' must match vc.credentialSubject.aud "
                f"'{self.vc.credentialSubject.aud}'."
            )
        return self
