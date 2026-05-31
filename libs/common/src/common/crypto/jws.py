"""JWS compact-serialization sign and verify utilities.

All operations run through :func:`~common.crypto.algorithms.assert_algorithm_allowed`
before touching any key material, so prohibited algorithms are rejected at the
envelope level before any cryptographic primitive is invoked.

Supported algorithms
--------------------
* ``EdDSA`` — Ed25519 keys via the :mod:`cryptography` library (required).
* ``ES256``  — P-256 ECDSA keys via the :mod:`cryptography` library (optional).

Design decisions
----------------
* This module does **not** depend on PyJWT, joserfc, or any third-party JWT
  library for the *signing* path so that algorithm enforcement is always
  under our control.  The standard library provides all required primitives
  via :mod:`cryptography`.
* The JWS compact serialization is used throughout the codebase.
  Flattened and general JWS JSON serialization are not supported.
* Header parameters are kept minimal: ``alg`` and ``kid`` only.
  Additional parameters (``typ``, ``cty``) may be supplied by callers.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

from common.crypto.algorithms import assert_algorithm_allowed, ProhibitedAlgorithmError  # noqa: F401

__all__ = [
    "sign_jws",
    "verify_jws",
    "JWSVerificationError",
    "ProhibitedAlgorithmError",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class JWSVerificationError(ValueError):
    """Raised when JWS signature verification fails for any reason.

    Callers should treat any instance of this exception as a hard rejection —
    do not attempt to recover or fall back to a weaker check.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    # Re-add stripped padding
    padding = 4 - len(text) % 4
    if padding != 4:
        text += "=" * padding
    return base64.urlsafe_b64decode(text)


def _build_signing_input(header_b64: str, payload_b64: str) -> bytes:
    """Return the ASCII bytes of ``BASE64URL(header) || '.' || BASE64URL(payload)``."""
    return f"{header_b64}.{payload_b64}".encode("ascii")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sign_jws(
    payload: bytes | dict[str, Any],
    private_key: Ed25519PrivateKey | EllipticCurvePrivateKey,
    *,
    kid: str,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    """Sign *payload* and return a JWS compact serialization string.

    Parameters
    ----------
    payload:
        Either raw bytes or a JSON-serialisable dict.  Dicts are serialised
        with :func:`json.dumps` using no unnecessary whitespace.
    private_key:
        An ``Ed25519PrivateKey`` (produces ``alg: EdDSA``) or an
        ``EllipticCurvePrivateKey`` on P-256 (produces ``alg: ES256``).
    kid:
        The key identifier to embed in the JOSE header.  Should be the
        full verification method ID, e.g.
        ``did:key:z6Mk...#z6Mk...``.
    extra_headers:
        Optional additional JOSE header parameters (e.g. ``{"typ": "vc+jwt"}``).
        Do **not** include ``alg`` or ``kid`` here; they are set automatically.

    Returns
    -------
    str
        JWS compact serialization: ``header.payload.signature``.

    Raises
    ------
    ProhibitedAlgorithmError
        If the key type maps to a prohibited algorithm (should not happen
        with supported key types, but guards against future additions).
    TypeError
        If *private_key* is not a supported type.
    """
    # Determine algorithm from key type
    if isinstance(private_key, Ed25519PrivateKey):
        alg = "EdDSA"
    elif isinstance(private_key, EllipticCurvePrivateKey):
        alg = "ES256"
    else:
        raise TypeError(
            f"Unsupported private key type: {type(private_key).__name__}. "
            "Use Ed25519PrivateKey (EdDSA) or EllipticCurvePrivateKey P-256 (ES256)."
        )

    # Enforcement: will raise ProhibitedAlgorithmError for disallowed algs
    assert_algorithm_allowed(alg)

    # Build header
    header: dict[str, Any] = {"alg": alg, "kid": kid}
    if extra_headers:
        # Do not allow callers to override alg or kid
        extra_headers.pop("alg", None)
        extra_headers.pop("kid", None)
        header.update(extra_headers)

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())

    # Encode payload
    if isinstance(payload, dict):
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    else:
        payload_bytes = payload
    payload_b64 = _b64url_encode(payload_bytes)

    signing_input = _build_signing_input(header_b64, payload_b64)

    # Sign
    if isinstance(private_key, Ed25519PrivateKey):
        signature_bytes = private_key.sign(signing_input)
    else:
        # ES256: deterministic ECDSA with SHA-256
        signature_bytes = private_key.sign(signing_input, ECDSA(SHA256()))

    signature_b64 = _b64url_encode(signature_bytes)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_jws(
    token: str,
    public_key: Ed25519PublicKey | EllipticCurvePublicKey,
) -> dict[str, Any]:
    """Verify and decode a JWS compact serialization.

    Parameters
    ----------
    token:
        JWS compact serialization string (``header.payload.signature``).
    public_key:
        Matching public key.  The algorithm must match the ``alg`` header.

    Returns
    -------
    dict
        The decoded JSON payload as a dict.

    Raises
    ------
    JWSVerificationError
        On any verification failure: bad format, prohibited algorithm, wrong
        key type, or invalid signature.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWSVerificationError(
            f"JWS compact serialization must have exactly 3 parts separated by '.', "
            f"got {len(parts)}."
        )

    header_b64, payload_b64, signature_b64 = parts

    # Decode header
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as exc:
        raise JWSVerificationError(f"Failed to decode JWS header: {exc}") from exc

    # Algorithm check — BEFORE any crypto operation
    alg = header.get("alg")
    try:
        assert_algorithm_allowed(alg)
    except Exception as exc:
        raise JWSVerificationError(str(exc)) from exc

    # Key type / alg consistency
    if alg == "EdDSA" and not isinstance(public_key, Ed25519PublicKey):
        raise JWSVerificationError(
            f"Algorithm 'EdDSA' requires an Ed25519PublicKey, "
            f"got {type(public_key).__name__}."
        )
    if alg == "ES256" and not isinstance(public_key, EllipticCurvePublicKey):
        raise JWSVerificationError(
            f"Algorithm 'ES256' requires an EllipticCurvePublicKey, "
            f"got {type(public_key).__name__}."
        )

    # Reconstruct and verify
    signing_input = _build_signing_input(header_b64, payload_b64)
    try:
        sig_bytes = _b64url_decode(signature_b64)
    except Exception as exc:
        raise JWSVerificationError(f"Failed to decode JWS signature: {exc}") from exc

    try:
        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(sig_bytes, signing_input)
        else:
            public_key.verify(sig_bytes, signing_input, ECDSA(SHA256()))
    except InvalidSignature as exc:
        raise JWSVerificationError("JWS signature verification failed.") from exc

    # Decode payload
    try:
        payload_bytes = _b64url_decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception as exc:
        raise JWSVerificationError(f"Failed to decode JWS payload: {exc}") from exc
