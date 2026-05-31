"""SessionTokenIssuer — producer-side session JWT lifecycle (TASK-065).

The session exchange is a two-step handshake:

1. Consumer calls ``GET /auth/nonce`` → receives a short-lived nonce.
2. Consumer presents its Discovery-issued SD-JWT with a KB-JWT that binds
   the nonce.  Producer verifies the SD-JWT + KB-JWT, then issues a
   short-lived *session JWT* that can be used as a fast-path ``Bearer``
   token for subsequent requests instead of re-presenting the full VP.

Session JWT
-----------
* ``typ: session+jwt``
* Signed by the *producer* sentinel using its Ed25519 key.
* Claims: ``iss`` (producer DID), ``sub`` (consumer DID), ``aud`` (producer
  DID), ``iat``, ``exp`` (``iat + session_token_ttl``), ``jti`` (UUID4),
  ``service_id``, ``env``, ``scope`` (list of scope entries from the
  SD-JWT access-grant VC).

Verification
------------
:meth:`SessionTokenIssuer.verify` performs:
1. Decode header + payload (no signature yet).
2. Check ``typ == session+jwt``.
3. Verify Ed25519 signature with the producer's public key (derived from its
   own private key bytes — no external lookup required).
4. Check ``exp > now`` and ``iss == aud == service_did``.
5. Return the ``sub`` (consumer DID) and ``scope`` list on success.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SESSION_TYP = "session+jwt"


@dataclass
class SessionTokenClaims:
    """Decoded and validated claims from a session JWT."""

    sub: str                      # consumer DID
    iss: str                      # producer DID
    aud: str                      # producer DID (same as iss)
    iat: int
    exp: int
    jti: str
    service_id: str
    env: str
    scope: List[Dict[str, Any]] = field(default_factory=list)


class SessionTokenIssuer:
    """Issues and verifies short-lived session JWTs for the fast-path protocol.

    Parameters
    ----------
    service_did:
        The producer sentinel's DID — used as ``iss`` and ``aud`` for issued
        tokens.
    private_key_bytes:
        Raw 32-byte Ed25519 private key of the producer sentinel.
    service_id:
        Service identifier embedded in the token claims.
    env:
        Deployment environment (``dev`` / ``test`` / ``prod``).
    token_ttl:
        Session token lifetime in seconds (default 900 = 15 min).
    """

    def __init__(
        self,
        *,
        service_did: str,
        private_key_bytes: bytes,
        service_id: str,
        env: str,
        token_ttl: int = 900,
    ) -> None:
        self._service_did = service_did
        self._private_key_bytes = private_key_bytes
        self._service_id = service_id
        self._env = env
        self._token_ttl = token_ttl

        # Pre-derive public key bytes once for fast verify calls
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self._public_key_bytes: bytes = priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def issue(
        self,
        consumer_did: str,
        scope: List[Dict[str, Any]] | None = None,
    ) -> str:
        """Issue a session JWT for the given consumer DID.

        Parameters
        ----------
        consumer_did:
            The DID of the authenticated consumer.
        scope:
            Optional list of scope entries copied from the SD-JWT payload.

        Returns
        -------
        str
            Compact JWT string signed by the producer key.
        """
        now = int(time.time())
        kid = f"{self._service_did}#{self._service_did.split(':', 2)[-1]}"

        payload: Dict[str, Any] = {
            "iss": self._service_did,
            "sub": consumer_did,
            "aud": self._service_did,
            "iat": now,
            "exp": now + self._token_ttl,
            "jti": str(uuid.uuid4()),
            "service_id": self._service_id,
            "env": self._env,
        }
        if scope:
            payload["scope"] = scope

        return _sign_jwt(
            header={"alg": "EdDSA", "typ": _SESSION_TYP, "kid": kid},
            payload=payload,
            private_key_bytes=self._private_key_bytes,
        )

    def verify(self, token: str) -> SessionTokenClaims:
        """Verify a session JWT previously issued by this producer.

        Parameters
        ----------
        token:
            Raw compact JWT string (no ``Bearer `` prefix).

        Returns
        -------
        SessionTokenClaims
            Decoded and validated claims.

        Raises
        ------
        ValueError
            On any verification failure — caller maps to HTTP 401.
        """
        header, payload, sig, signing_input = _decode_parts(token)

        # 1. Type check
        if header.get("typ") != _SESSION_TYP:
            raise ValueError(f"Expected typ={_SESSION_TYP}, got {header.get('typ')!r}")

        # 2. Algorithm check
        if header.get("alg") != "EdDSA":
            raise ValueError(f"Unsupported alg: {header.get('alg')!r}")

        # 3. Signature verification
        _verify_ed25519(self._public_key_bytes, signing_input, sig)

        # 4. Expiry
        now = int(time.time())
        exp = int(payload.get("exp", 0))
        if exp <= now:
            raise ValueError("Session token has expired")

        # 5. Audience / issuer binding
        if payload.get("iss") != self._service_did:
            raise ValueError("Session token iss mismatch")
        if payload.get("aud") != self._service_did:
            raise ValueError("Session token aud mismatch")

        sub = payload.get("sub", "")
        if not sub:
            raise ValueError("Session token missing sub")

        return SessionTokenClaims(
            sub=sub,
            iss=payload["iss"],
            aud=payload["aud"],
            iat=int(payload.get("iat", 0)),
            exp=exp,
            jti=payload.get("jti", ""),
            service_id=payload.get("service_id", ""),
            env=payload.get("env", ""),
            scope=payload.get("scope", []),
        )


# ---------------------------------------------------------------------------
# Internal helpers (mirrors sd_jwt.py to avoid circular import)
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    import base64
    padded = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_parts(jwt_str: str) -> tuple[dict, dict, bytes, bytes]:
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError("Not a compact JWT")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2])
        signing_input = f"{parts[0]}.{parts[1]}".encode()
    except Exception as exc:
        raise ValueError(f"JWT decode error: {exc}") from exc
    return header, payload, sig, signing_input


def _sign_jwt(header: dict, payload: dict, private_key_bytes: bytes) -> str:
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
        raise ValueError("Ed25519 signature verification failed")
    except Exception as exc:
        raise ValueError(str(exc)) from exc
