"""VC and VP verification functions (TASK-041)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional, Set

from common.vc_engine.errors import VCError, VCErrorCode, VPError, VPErrorCode
from common.vc_engine.resolver import DIDResolver

# Re-export SD-JWT verification so callers can import from one place
from common.vc_engine.sd_jwt import verify_sd_jwt_with_kb as verify_sd_jwt_with_kb  # noqa: F401


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VerifiedCredential:
    issuer_did: str
    subject_did: str
    credential_type: str
    claims: dict
    exp: Optional[float]
    nbf: Optional[float]
    jti: str
    raw_jwt: str


@dataclass
class VerifiedPresentation:
    holder_did: str
    presentation_id: str
    vcs: List[VerifiedCredential]
    exp: Optional[float]
    raw_jwt: str


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_jwt_parts(jwt_str: str) -> tuple[dict, dict, bytes, bytes]:
    """Return (header, payload, signature_bytes, signing_input_bytes)."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise VCError(VCErrorCode.PARSE_ERROR, "Not a compact JWT (expected 3 parts)")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
        signing_input = f"{parts[0]}.{parts[1]}".encode()
    except Exception as exc:
        raise VCError(VCErrorCode.PARSE_ERROR, f"JWT decode error: {exc}") from exc
    return header, payload, signature, signing_input


def _verify_ed25519_signature(
    public_key_bytes: bytes,
    signing_input: bytes,
    signature: bytes,
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(signature, signing_input)
    except InvalidSignature:
        raise VCError(VCErrorCode.SIGNATURE_INVALID, "Ed25519 signature verification failed")
    except Exception as exc:
        raise VCError(VCErrorCode.SIGNATURE_INVALID, str(exc)) from exc


# ---------------------------------------------------------------------------
# verify_vc
# ---------------------------------------------------------------------------

async def verify_vc(
    vc_jwt: str,
    trusted_issuer_dids: Set[str],
    resolver: DIDResolver,
    now: Optional[float] = None,
    status_checker: Optional[Callable[[str, int], Awaitable[bool]]] = None,
    schema_validator: Optional[Callable[[dict], bool]] = None,
) -> VerifiedCredential:
    """Verify a JWT-VC and return a VerifiedCredential.

    Raises:
        VCError: on any validation failure.
    """
    now = now or time.time()

    header, payload, signature, signing_input = _decode_jwt_parts(vc_jwt)

    # Validate type header
    if header.get("typ") not in ("vc+jwt", "JWT"):
        # Accept both vc+jwt and plain JWT for compatibility
        pass

    # Resolve issuer
    issuer_did = payload.get("iss", "")
    if not issuer_did:
        raise VCError(VCErrorCode.PARSE_ERROR, "Missing 'iss' claim")

    alg = header.get("alg", "EdDSA")
    if alg in ("EdDSA", "Ed25519"):
        did_doc = await resolver.resolve(issuer_did)
        vm = did_doc.first_verification_method
        if vm is None:
            raise VCError(VCErrorCode.DID_UNRESOLVABLE, f"No verification method for {issuer_did}")
        _verify_ed25519_signature(vm.public_key_bytes, signing_input, signature)
    elif alg == "none":
        # Unsigned JWT — only accepted if the JWT has an empty signature part
        if signature:
            raise VCError(VCErrorCode.SIGNATURE_INVALID, "alg=none but signature is non-empty")
    else:
        raise VCError(VCErrorCode.SIGNATURE_INVALID, f"Unsupported algorithm: {alg!r}")

    # Check trusted issuer
    if issuer_did not in trusted_issuer_dids:
        raise VCError(VCErrorCode.ISSUER_UNTRUSTED, f"Issuer {issuer_did!r} not in trusted set")

    # Check expiry
    exp = payload.get("exp")
    if exp is not None and float(exp) < now:
        raise VCError(VCErrorCode.VC_EXPIRED, f"Credential expired at {exp}")

    # Check nbf
    nbf = payload.get("nbf")
    if nbf is not None and float(nbf) > now:
        raise VCError(VCErrorCode.VC_NBF, f"Credential not yet valid (nbf={nbf})")

    # Check jti
    jti = payload.get("jti", "")

    # Extract vc claim
    vc_claim = payload.get("vc", {})
    if not vc_claim and "credentialSubject" in payload:
        vc_claim = payload  # flat JWT-VC style

    subject = vc_claim.get("credentialSubject", {})
    subject_did = subject.get("id", payload.get("sub", ""))
    cred_type = vc_claim.get("type", ["VerifiableCredential"])
    if isinstance(cred_type, list):
        cred_type = cred_type[-1] if cred_type else "VerifiableCredential"

    # Schema validation
    if schema_validator is not None:
        if not schema_validator(subject):
            raise VCError(VCErrorCode.SCHEMA_MISMATCH, "credentialSubject failed schema validation")

    # Status revocation check
    if status_checker is not None:
        cred_status = vc_claim.get("credentialStatus", payload.get("credentialStatus"))
        if cred_status:
            status_list_id = cred_status.get("statusListCredential", "")
            status_index = int(cred_status.get("statusListIndex", 0))
            revoked = await status_checker(status_list_id, status_index)
            if revoked:
                raise VCError(VCErrorCode.STATUS_REVOKED, f"Credential {jti[:16] or 'unknown'} is revoked")

    return VerifiedCredential(
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=cred_type,
        claims=subject,
        exp=float(exp) if exp is not None else None,
        nbf=float(nbf) if nbf is not None else None,
        jti=jti,
        raw_jwt=vc_jwt,
    )


# ---------------------------------------------------------------------------
# verify_vp
# ---------------------------------------------------------------------------

async def verify_vp(
    vp_jwt: str,
    expected_aud: str,
    expected_nonce: Optional[str],
    expected_env: Optional[str],
    resolver: DIDResolver,
    trusted_issuer_dids: Optional[Set[str]] = None,
    now: Optional[float] = None,
) -> VerifiedPresentation:
    """Verify a JWT-VP and all embedded VCs.

    Raises:
        VPError: on any presentation-level failure.
        VCError: propagated from inner verify_vc calls.
    """
    now = now or time.time()

    try:
        header, payload, signature, signing_input = _decode_jwt_parts(vp_jwt)
    except VCError as exc:
        raise VPError(VPErrorCode.VP_INVALID, str(exc)) from exc

    # Verify outer VP signature
    alg = header.get("alg", "EdDSA")
    holder_did = payload.get("iss", "")
    if not holder_did:
        raise VPError(VPErrorCode.VP_INVALID, "Missing 'iss' claim in VP")

    if alg in ("EdDSA", "Ed25519"):
        try:
            did_doc = await resolver.resolve(holder_did)
            vm = did_doc.first_verification_method
            if vm is None:
                raise VPError(VPErrorCode.VP_INVALID, f"No verification method for {holder_did}")
            _verify_ed25519_signature(vm.public_key_bytes, signing_input, signature)
        except VCError as exc:
            raise VPError(VPErrorCode.VP_INVALID, str(exc)) from exc
    elif alg == "none":
        if signature:
            raise VPError(VPErrorCode.VP_INVALID, "alg=none but signature is non-empty")
    else:
        raise VPError(VPErrorCode.VP_INVALID, f"Unsupported algorithm: {alg!r}")

    # Check audience (constant-time compare)
    aud = payload.get("aud", "")
    if not hmac.compare_digest(aud, expected_aud):
        raise VPError(VPErrorCode.VP_AUD_MISMATCH, f"aud mismatch: got {aud!r}, expected {expected_aud!r}")

    # Check nonce
    if expected_nonce is not None:
        nonce = payload.get("nonce", "")
        if not hmac.compare_digest(nonce, expected_nonce):
            raise VPError(VPErrorCode.VP_NONCE_MISMATCH, "nonce mismatch")

    # Check expiry
    exp = payload.get("exp")
    if exp is not None and float(exp) < now:
        raise VPError(VPErrorCode.VP_EXPIRED, "VP has expired")

    # Check env
    if expected_env is not None:
        env = payload.get("env", "")
        if env != expected_env:
            raise VPError(VPErrorCode.VP_INVALID, f"env mismatch: {env!r} != {expected_env!r}")

    # Verify embedded VCs
    vp_claim = payload.get("vp", {})
    vc_list: list[str] = vp_claim.get("verifiableCredential", [])
    verified_vcs: list[VerifiedCredential] = []

    issuers = trusted_issuer_dids or set()
    for vc_jwt in vc_list:
        try:
            vc = await verify_vc(vc_jwt, issuers, resolver, now=now)
            verified_vcs.append(vc)
        except VCError as exc:
            raise VPError(VPErrorCode.VC_ERROR, str(exc)) from exc

    return VerifiedPresentation(
        holder_did=holder_did,
        presentation_id=payload.get("jti", ""),
        vcs=verified_vcs,
        exp=float(exp) if exp is not None else None,
        raw_jwt=vp_jwt,
    )
