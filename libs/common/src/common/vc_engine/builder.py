"""VP builder — create_vp (TASK-041)."""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import List


def create_vp(
    vcs: List[str],
    holder_did: str,
    holder_key_bytes: bytes,
    aud: str,
    nonce: str,
    env: str,
    exp_seconds: int = 300,
) -> str:
    """Create a signed JWT-VP (Verifiable Presentation).

    Args:
        vcs:             List of compact JWT-VC strings to include.
        holder_did:      DID of the VP holder (iss).
        holder_key_bytes: Raw 32-byte Ed25519 private key.
        aud:             Audience (the verifier's DID or URL).
        nonce:           Challenge nonce to bind the presentation.
        env:             Environment tag (e.g. "prod").
        exp_seconds:     TTL in seconds (default 5 min).

    Returns:
        Compact JWT-VP string.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    now = int(time.time())
    payload = {
        "iss": holder_did,
        "aud": aud,
        "nonce": nonce,
        "iat": now,
        "exp": now + exp_seconds,
        "jti": str(uuid.uuid4()),
        "env": env,
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": vcs,
        },
    }

    # Key ID: holder_did + first 8 chars of method-specific-id
    kid = f"{holder_did}#{holder_did[8:16]}" if holder_did.startswith("did:key:z") else f"{holder_did}#key-1"

    header = {
        "alg": "EdDSA",
        "typ": "vp+jwt",
        "kid": kid,
    }

    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    signing_input = f"{header_b64}.{payload_b64}".encode()
    privkey = Ed25519PrivateKey.from_private_bytes(holder_key_bytes)
    signature = privkey.sign(signing_input)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{sig_b64}"
