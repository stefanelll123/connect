"""DID resolution and Proof-of-Possession (PoP) signature verification.

MVP: Supports did:key only (self-contained, no network resolution needed).

did:key format:  did:key:<multibase-encoded-public-key>
  Multibase prefix 'z' = base58btc

After base58btc decode the first bytes are a multicodec varint:
  Ed25519 public key:  0xed 0x01  (code 0xed = 237)
  P-256   public key:  0x80 0x24  (code 0x1200 = 4608)

PoP message that is signed:
    json.dumps({"challenge_nonce": ..., "did": ..., "iat": ..., "jti": ...},
               sort_keys=True).encode()

proof_value is multibase-encoded:
  'z' prefix → base58btc → raw signature bytes
  For Ed25519: 64-byte raw signature
  For P-256:   DER-encoded ECDSA-SHA256 signature
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# base58btc decode (no external dependency)
# ---------------------------------------------------------------------------
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _base58_decode(s: str) -> bytes:
    n = 0
    for char in s.encode():
        n = n * 58 + _B58_MAP[char]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")  # empty if n==0
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


# ---------------------------------------------------------------------------
# Multicodec varint parsing
# ---------------------------------------------------------------------------

def _read_varint(data: bytes) -> tuple[int, int]:
    """Return (value, bytes_consumed) for an unsigned LEB128 varint."""
    n = 0
    shift = 0
    for i, byte in enumerate(data):
        n |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return n, i + 1
        shift += 7
    raise ValueError("Truncated varint")


# ---------------------------------------------------------------------------
# DID key parsing
# ---------------------------------------------------------------------------

class DIDResolutionError(Exception):
    pass


class InvalidSignatureError(Exception):
    pass


class UnsupportedDIDMethodError(Exception):
    pass


def _load_did_key(did: str) -> tuple[str, bytes]:
    """Parse a did:key DID and return (algorithm, raw_public_key_bytes).

    Returns:
        ("Ed25519", 32 bytes)  for Ed25519 keys
        ("P-256",   33 bytes)  for P-256 compressed keys

    Raises:
        DIDResolutionError: on any parse or format error.
        UnsupportedDIDMethodError: for DID methods other than did:key.
    """
    if not did.startswith("did:"):
        raise DIDResolutionError(f"Not a valid DID: {did!r}")

    parts = did.split(":", 2)
    if len(parts) < 3 or parts[1] != "key":
        raise UnsupportedDIDMethodError(
            f"Only did:key is supported in this environment; got {did!r}"
        )

    multibase = parts[2]
    if not multibase.startswith("z"):
        raise DIDResolutionError(
            f"did:key multibase must use base58btc ('z' prefix); got {multibase[0]!r}"
        )

    try:
        decoded = _base58_decode(multibase[1:])
    except (KeyError, ValueError) as exc:
        raise DIDResolutionError(f"base58btc decode failed: {exc}") from exc

    code, offset = _read_varint(decoded)
    raw_key = decoded[offset:]

    if code == 0xED:  # Ed25519 (varint 0xed = 237; single byte since < 0x80 is false — wait)
        # 0xed = 237, > 127 so varint is 2 bytes: 0xed 0x01 → value = 237
        return "Ed25519", raw_key
    elif code == 0x1200:  # P-256 (varint 0x80 0x24 → value = 4608)
        return "P-256", raw_key
    else:
        raise DIDResolutionError(f"Unsupported multicodec key type: 0x{code:x}")


# ---------------------------------------------------------------------------
# PoP verification
# ---------------------------------------------------------------------------

def _verify_ed25519(raw_pub: bytes, message: bytes, signature: bytes) -> None:
    """Verify Ed25519 signature; raises InvalidSignatureError on failure."""
    try:
        key = Ed25519PublicKey.from_public_bytes(raw_pub)
        key.verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise InvalidSignatureError("Ed25519 signature verification failed") from exc


def _verify_p256(raw_pub_compressed: bytes, message: bytes, signature_der: bytes) -> None:
    """Verify P-256 ECDSA-SHA256 DER signature; raises InvalidSignatureError on failure."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        EllipticCurvePublicNumbers,
        ECDSA,
    )
    from cryptography.hazmat.primitives import hashes

    if len(raw_pub_compressed) != 33:
        raise InvalidSignatureError("Invalid P-256 compressed key length")

    prefix = raw_pub_compressed[0]
    x_int = int.from_bytes(raw_pub_compressed[1:33], "big")

    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    b_const = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    y_sq = (pow(x_int, 3, p) - 3 * x_int + b_const) % p
    y_int = pow(y_sq, (p + 1) // 4, p)

    # Select parity
    if prefix == 0x02 and (y_int % 2 != 0):
        y_int = p - y_int
    elif prefix == 0x03 and (y_int % 2 == 0):
        y_int = p - y_int

    nums = EllipticCurvePublicNumbers(x=x_int, y=y_int, curve=SECP256R1())
    try:
        public_key = nums.public_key()
        public_key.verify(signature_der, message, ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise InvalidSignatureError("P-256 ECDSA signature verification failed") from exc


def _decode_proof_value(proof_value: str) -> bytes:
    """Decode a multibase proof_value (z = base58btc) to raw bytes."""
    if proof_value.startswith("z"):
        return _base58_decode(proof_value[1:])
    # Fallback: try base64url
    import base64
    return base64.urlsafe_b64decode(proof_value + "==")


async def verify_renewal_assertion(
    did: str,
    sentinel_id: str,
    iat: int,
    proof_value: str,
    *,
    max_iat_skew_seconds: int = 60,
) -> None:
    """Verify a self-signed renewal assertion (no nonce / enrollment token needed).

    The sentinel proves ownership of its DID key by signing::

        json.dumps({"action": "sentinel_auth_renew", "did": <did>,
                    "iat": <now>, "sentinel_id": <id>}, sort_keys=True)

    Raises:
        DIDResolutionError, InvalidSignatureError, UnsupportedDIDMethodError, ValueError
    """
    now = int(time.time())
    if abs(now - iat) > max_iat_skew_seconds:
        raise ValueError(
            f"Renewal assertion iat is {abs(now - iat)}s old — exceeds {max_iat_skew_seconds}s limit"
        )

    payload = {
        "action": "sentinel_auth_renew",
        "did": did,
        "iat": iat,
        "sentinel_id": sentinel_id,
    }
    message = json.dumps(payload, sort_keys=True).encode()

    alg, raw_pub = _load_did_key(did)
    try:
        signature = _decode_proof_value(proof_value)
    except Exception as exc:
        raise InvalidSignatureError(f"Cannot decode proof_value: {exc}") from exc

    if alg == "Ed25519":
        _verify_ed25519(raw_pub, message, signature)
    elif alg == "P-256":
        _verify_p256(raw_pub, message, signature)
    else:
        raise UnsupportedDIDMethodError(f"No verifier for algorithm {alg!r}")


async def verify_pop(
    did: str,
    pop_payload: dict,
    proof_value: str,
    *,
    max_iat_skew_seconds: int = 30,
) -> None:
    """Verify a DID Proof-of-Possession.

    Args:
        did: the claimed DID (e.g. "did:key:z6Mk...")
        pop_payload: {"jti", "did", "challenge_nonce", "iat"}
        proof_value: base58btc-encoded signature (multibase 'z' prefix)
        max_iat_skew_seconds: max allowed clock drift for iat

    Raises:
        DIDResolutionError: cannot resolve the DID.
        InvalidSignatureError: signature verification failed.
        UnsupportedDIDMethodError: DID method not supported.
        ValueError: PoP payload missing required fields or iat too old.
    """
    required = {"jti", "did", "challenge_nonce", "iat"}
    missing = required - set(pop_payload.keys())
    if missing:
        raise ValueError(f"PoP payload missing fields: {missing}")

    # Clock drift protection
    now = int(time.time())
    iat = int(pop_payload["iat"])
    if abs(now - iat) > max_iat_skew_seconds:
        raise ValueError(
            f"PoP iat is {abs(now - iat)}s from now — exceeds {max_iat_skew_seconds}s skew limit"
        )

    # did in PoP must match the claimed DID
    if pop_payload["did"] != did:
        raise ValueError("DID in PoP payload does not match claimed DID")

    # Canonical message: sorted-key JSON
    message = json.dumps(pop_payload, sort_keys=True).encode()

    # Resolve DID key
    alg, raw_pub = _load_did_key(did)

    # Decode signature
    try:
        signature = _decode_proof_value(proof_value)
    except Exception as exc:
        raise InvalidSignatureError(f"Cannot decode proof_value: {exc}") from exc

    # Verify
    if alg == "Ed25519":
        _verify_ed25519(raw_pub, message, signature)
    elif alg == "P-256":
        _verify_p256(raw_pub, message, signature)
    else:
        raise UnsupportedDIDMethodError(f"No verifier for algorithm {alg!r}")
