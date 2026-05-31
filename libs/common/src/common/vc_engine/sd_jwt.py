"""SD-JWT + KB-JWT primitives (RFC draft-ietf-oauth-selective-disclosure-jwt).

Implements the subset needed for the sentinel trust layer:

* :func:`build_sd_jwt`           — produce an issuer-signed SD-JWT (EdDSA/Ed25519)
* :func:`build_kb_jwt`           — produce a holder Key-Binding JWT bound to an SD-JWT
* :func:`build_sd_presentation`  — assemble the ``<SD-JWT>~[disc~]...<KB-JWT>`` string
* :func:`parse_sd_presentation`  — split a presentation back into its components
* :func:`verify_sd_jwt_with_kb`  — full issuer-sig + cnf/KB verification, returns
                                   :class:`~common.vc_engine.verifier.VerifiedCredential`

Design constraints
------------------
* No new library dependencies — all crypto via :mod:`cryptography` + manual base64url.
* Phase-B uses *full disclosure* (``_sd: []``).  Selective disclosure over individual
  claims is a future extension: add claim salts to ``_sd`` and pass matching
  ``disclosures`` to :func:`build_sd_presentation`.
* Algorithm: EdDSA (Ed25519) only, consistent with the rest of the codebase.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import TYPE_CHECKING, Optional, Set

from common.vc_engine.errors import VCError, VCErrorCode
from common.vc_engine.resolver import DIDResolver

if TYPE_CHECKING:
    from common.vc_engine.verifier import VerifiedCredential

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    """URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_parts(jwt_str: str) -> tuple[dict, dict, bytes, bytes]:
    """Decode a compact JWT into (header, payload, sig_bytes, signing_input)."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise VCError(VCErrorCode.PARSE_ERROR, "Not a compact JWT (expected 3 parts)")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2])
        signing_input = f"{parts[0]}.{parts[1]}".encode()
    except Exception as exc:
        raise VCError(VCErrorCode.PARSE_ERROR, f"JWT decode error: {exc}") from exc
    return header, payload, sig, signing_input


def _sign_jwt(header: dict, payload: dict, private_key_bytes: bytes) -> str:
    """Sign a JWT using Ed25519 and return the compact serialisation."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig = key.sign(signing_input)
    return f"{h}.{p}.{_b64url(sig)}"


def _verify_ed25519(public_key_bytes: bytes, signing_input: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, signing_input)
    except InvalidSignature:
        raise VCError(VCErrorCode.SIGNATURE_INVALID, "Ed25519 signature verification failed")
    except Exception as exc:
        raise VCError(VCErrorCode.SIGNATURE_INVALID, str(exc)) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_sd_jwt(
    payload: dict,
    issuer_private_key_bytes: bytes,
    kid: str,
    disclosable_claims: list[str] | None = None,
) -> str:
    """Build an issuer-signed SD-JWT.

    Parameters
    ----------
    payload:
        Full JWT payload dict.  A ``cnf`` key with the holder's JWK **must**
        already be present.  An ``_sd`` array is added automatically (empty
        for full-disclosure mode).
    issuer_private_key_bytes:
        Raw 32-byte Ed25519 private key of the issuer.
    kid:
        Key identifier placed in the JWT header (e.g. ``did#fragment``).
    disclosable_claims:
        Reserved for future selective-disclosure use.  Pass ``None`` or ``[]``
        for full-disclosure mode.

    Returns
    -------
    str
        Compact JWT string (the SD-JWT proper, without any disclosures or KB-JWT).
    """
    if "cnf" not in payload:
        raise VCError(VCErrorCode.PARSE_ERROR, "SD-JWT payload must contain 'cnf' claim")

    sd_payload = dict(payload)
    # Full-disclosure mode: empty _sd array (no hidden claims)
    sd_payload.setdefault("_sd", [])
    sd_payload.setdefault("_sd_alg", "sha-256")

    header = {"alg": "EdDSA", "typ": "sd+jwt", "kid": kid}
    return _sign_jwt(header, sd_payload, issuer_private_key_bytes)


def build_kb_jwt(
    sd_jwt_str: str,
    aud: str,
    nonce: str,
    holder_private_key_bytes: bytes,
    exp_seconds: int = 60,
) -> str:
    """Build a Key-Binding JWT tied to a specific SD-JWT.

    The ``sd_hash`` claim is ``base64url(SHA-256(ascii(sd_jwt_str)))`` which
    cryptographically ties the KB-JWT to the exact SD-JWT token.

    Parameters
    ----------
    sd_jwt_str:
        The compact SD-JWT string (issuer part only, without disclosures or
        prior KB-JWT).
    aud:
        Audience — the producer/verifier DID this presentation is intended for.
    nonce:
        Single-use nonce obtained from the verifier's ``GET /auth/nonce`` endpoint.
    holder_private_key_bytes:
        Raw 32-byte Ed25519 private key of the holder (consumer sentinel).
    exp_seconds:
        Lifetime of the KB-JWT in seconds (default 60).

    Returns
    -------
    str
        Compact JWT string for the Key-Binding JWT.
    """
    sd_hash = _b64url(hashlib.sha256(sd_jwt_str.encode("ascii")).digest())
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + exp_seconds,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": sd_hash,
    }
    # typ is placed in the header per SD-JWT spec
    header = {"alg": "EdDSA", "typ": "kb+jwt"}
    return _sign_jwt(header, payload, holder_private_key_bytes)


def build_sd_presentation(
    sd_jwt: str,
    disclosures: list[str],
    holder_private_key_bytes: bytes,
    aud: str,
    nonce: str,
    kb_exp_seconds: int = 60,
) -> str:
    """Assemble a full SD-JWT presentation: ``<SD-JWT>~[disc~]...<KB-JWT>``.

    With zero disclosures (full-disclosure mode) this produces ``<SD-JWT>~~<KB-JWT>``.

    Parameters
    ----------
    sd_jwt:
        The issuer SD-JWT compact string.
    disclosures:
        List of base64url-encoded disclosure strings.  Empty list for
        full-disclosure mode.
    holder_private_key_bytes:
        Raw 32-byte Ed25519 private key of the holder.
    aud:
        Audience DID for the KB-JWT.
    nonce:
        Single-use nonce for the KB-JWT.
    kb_exp_seconds:
        KB-JWT lifetime in seconds.

    Returns
    -------
    str
        Presentation string suitable for the ``SentinelVP`` header.
    """
    kb_jwt = build_kb_jwt(sd_jwt, aud, nonce, holder_private_key_bytes, kb_exp_seconds)
    parts = [sd_jwt] + disclosures + [kb_jwt]
    return "~".join(parts)


def parse_sd_presentation(presentation: str) -> tuple[str, list[str], str]:
    """Split a ``<SD-JWT>~[disc~]...<KB-JWT>`` presentation string.

    Parameters
    ----------
    presentation:
        The raw presentation string from the ``SentinelVP`` header.

    Returns
    -------
    tuple[str, list[str], str]
        ``(sd_jwt, disclosures, kb_jwt)``

    Raises
    ------
    VCError(PARSE_ERROR)
        If the string does not have the expected format (missing ``~``).
    """
    parts = presentation.split("~")
    # Minimum: SD-JWT (index 0) + empty-disclosure separator + KB-JWT (last)
    # e.g. "header.payload.sig~~header.payload.sig" → ["hdr...", "", "hdr..."]
    if len(parts) < 2:
        raise VCError(VCErrorCode.PARSE_ERROR, "Not a valid SD-JWT presentation (no '~' separator)")

    sd_jwt = parts[0]
    kb_jwt = parts[-1]
    disclosures = parts[1:-1]

    if not sd_jwt:
        raise VCError(VCErrorCode.PARSE_ERROR, "SD-JWT part is empty")
    if not kb_jwt:
        raise VCError(VCErrorCode.PARSE_ERROR, "KB-JWT part is empty")

    return sd_jwt, disclosures, kb_jwt


async def verify_sd_jwt_with_kb(
    presentation: str,
    trusted_issuer_dids: Set[str],
    resolver: DIDResolver,
    aud: str,
    nonce: str,
    now: Optional[float] = None,
) -> VerifiedCredential:
    """Verify a full SD-JWT presentation including the Key-Binding JWT.

    Verification steps
    ------------------
    1. Parse ``<SD-JWT>~[disc~]...<KB-JWT>``.
    2. Verify the issuer's Ed25519 signature on the SD-JWT.
    3. Check that the issuer DID is in ``trusted_issuer_dids``.
    4. Extract ``cnf.jwk.x`` — the holder's public key.
    5. Verify the KB-JWT's Ed25519 signature with the holder public key.
    6. Check KB-JWT claims: ``aud``, ``nonce``, ``exp``, ``typ``.
    7. Recompute ``sd_hash`` and compare with KB-JWT claim.
    8. Check SD-JWT ``exp`` / ``nbf``.
    9. Return :class:`~common.vc_engine.verifier.VerifiedCredential`.

    Parameters
    ----------
    presentation:
        Raw ``SentinelVP`` header value.
    trusted_issuer_dids:
        Set of issuer DIDs pre-verified as active on-chain (from
        ``TrustLayerClient.is_issuer_trusted``).
    resolver:
        DID resolver (resolves ``did:key`` locally, ``did:ethr`` via chain).
    aud:
        Expected audience (this producer's DID).
    nonce:
        Expected nonce (must match the KB-JWT ``nonce`` claim exactly).
    now:
        Override current time (seconds since epoch).  Defaults to
        ``time.time()``.

    Returns
    -------
    VerifiedCredential
        Populated from the SD-JWT issuer payload.

    Raises
    ------
    VCError
        On any verification failure.
    """
    now = now or time.time()

    # ── 1. Parse presentation ─────────────────────────────────────────────
    sd_jwt, disclosures, kb_jwt = parse_sd_presentation(presentation)

    # ── 2. Verify issuer signature on SD-JWT ──────────────────────────────
    sd_header, sd_payload, sd_sig, sd_signing_input = _decode_parts(sd_jwt)

    issuer_did = sd_payload.get("iss", "")
    if not issuer_did:
        raise VCError(VCErrorCode.PARSE_ERROR, "SD-JWT missing 'iss' claim")

    alg = sd_header.get("alg", "EdDSA")
    if alg not in ("EdDSA", "Ed25519"):
        raise VCError(VCErrorCode.SIGNATURE_INVALID, f"Unsupported SD-JWT algorithm: {alg!r}")

    did_doc = await resolver.resolve(issuer_did)
    vm = did_doc.first_verification_method
    if vm is None:
        raise VCError(VCErrorCode.DID_UNRESOLVABLE, f"No verification method for {issuer_did}")
    _verify_ed25519(vm.public_key_bytes, sd_signing_input, sd_sig)

    # ── 3. Check trusted issuer ───────────────────────────────────────────
    if issuer_did not in trusted_issuer_dids:
        raise VCError(VCErrorCode.ISSUER_UNTRUSTED, f"Issuer {issuer_did!r} not in trusted set")

    # ── 4. Extract cnf.jwk — holder's public key ──────────────────────────
    cnf = sd_payload.get("cnf")
    if not cnf or "jwk" not in cnf:
        raise VCError(VCErrorCode.PARSE_ERROR, "SD-JWT missing 'cnf.jwk' claim (no key binding)")

    jwk = cnf["jwk"]
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise VCError(VCErrorCode.SIGNATURE_INVALID, "cnf.jwk must be an OKP Ed25519 key")

    try:
        holder_pub_bytes = _b64url_decode(jwk["x"])
    except Exception as exc:
        raise VCError(VCErrorCode.PARSE_ERROR, f"Cannot decode cnf.jwk.x: {exc}") from exc

    if len(holder_pub_bytes) != 32:
        raise VCError(VCErrorCode.SIGNATURE_INVALID, "cnf.jwk.x must be 32 bytes (Ed25519)")

    # ── 5. Verify KB-JWT signature ────────────────────────────────────────
    kb_header, kb_payload, kb_sig, kb_signing_input = _decode_parts(kb_jwt)

    kb_alg = kb_header.get("alg", "EdDSA")
    if kb_alg not in ("EdDSA", "Ed25519"):
        raise VCError(VCErrorCode.SIGNATURE_INVALID, f"Unsupported KB-JWT algorithm: {kb_alg!r}")

    _verify_ed25519(holder_pub_bytes, kb_signing_input, kb_sig)

    # ── 6. KB-JWT claims ──────────────────────────────────────────────────
    if kb_header.get("typ") != "kb+jwt":
        raise VCError(VCErrorCode.PARSE_ERROR, "KB-JWT header 'typ' must be 'kb+jwt'")

    kb_exp = kb_payload.get("exp")
    if kb_exp is None or float(kb_exp) < now:
        raise VCError(VCErrorCode.VC_EXPIRED, "KB-JWT has expired")

    kb_aud = kb_payload.get("aud", "")
    import hmac as _hmac
    if not _hmac.compare_digest(kb_aud, aud):
        raise VCError(VCErrorCode.ISSUER_UNTRUSTED, f"KB-JWT aud mismatch: got {kb_aud!r}, expected {aud!r}")

    kb_nonce = kb_payload.get("nonce", "")
    if not _hmac.compare_digest(kb_nonce, nonce):
        raise VCError(VCErrorCode.PARSE_ERROR, "KB-JWT nonce mismatch")

    # ── 7. Verify sd_hash ─────────────────────────────────────────────────
    expected_sd_hash = _b64url(hashlib.sha256(sd_jwt.encode("ascii")).digest())
    kb_sd_hash = kb_payload.get("sd_hash", "")
    if not _hmac.compare_digest(kb_sd_hash, expected_sd_hash):
        raise VCError(VCErrorCode.SIGNATURE_INVALID, "KB-JWT sd_hash does not match SD-JWT")

    # ── 8. SD-JWT expiry / nbf ────────────────────────────────────────────
    exp = sd_payload.get("exp")
    if exp is not None and float(exp) < now:
        raise VCError(VCErrorCode.VC_EXPIRED, f"SD-JWT expired at {exp}")

    nbf = sd_payload.get("nbf")
    if nbf is not None and float(nbf) > now:
        raise VCError(VCErrorCode.VC_NBF, f"SD-JWT not yet valid (nbf={nbf})")

    # ── 9. Build VerifiedCredential ───────────────────────────────────────
    from common.vc_engine.verifier import VerifiedCredential  # deferred to avoid circular import
    # Apply disclosures (currently no-op for full-disclosure mode)
    # In the future: decode each disclosure salt+value pair and reconstruct claims
    vc_claim = sd_payload.get("vc", {})
    subject = vc_claim.get("credentialSubject", sd_payload.get("credentialSubject", {}))
    subject_did = subject.get("id", sd_payload.get("sub", ""))
    cred_type = vc_claim.get("type", ["VerifiableCredential"])
    if isinstance(cred_type, list):
        cred_type = cred_type[-1] if cred_type else "VerifiableCredential"
    jti = sd_payload.get("jti", "")

    return VerifiedCredential(
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=cred_type,
        claims=subject,
        exp=float(exp) if exp is not None else None,
        nbf=float(nbf) if nbf is not None else None,
        jti=jti,
        raw_jwt=sd_jwt,
    )
