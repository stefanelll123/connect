"""ProofClaims JWT builder for the Consumer Sentinel.

The Consumer Sentinel calls :func:`build_proof` once per outgoing request,
immediately before attaching the resulting compact JWS to the
``Authorization: SentinelProof <jws>`` HTTP header.

Security note: the ``jti`` is a UUIDv4 generated fresh for every call —
reusing a jti across requests would defeat replay protection.
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.crypto.jws import sign_jws
from common.proof.hash_utils import EMPTY_HASH, hash_body, hash_query, normalize_content_type
from common.proof.models import (
    DEFAULT_PROOF_TTL,
    MAX_PROOF_TTL,
    PROOF_TYP,
    ProofClaims,
    ReqBinding,
)

__all__ = ["build_proof", "build_req_binding"]


def build_req_binding(
    *,
    method: str,
    path: str,
    raw_query: str = "",
    body: bytes = b"",
    content_type: Optional[str] = None,
) -> ReqBinding:
    """Construct and validate a :class:`~common.proof.models.ReqBinding`.

    Args:
        method: HTTP method (``GET``, ``POST``, …).  Will be upper-cased.
        path: URL-decoded path with leading slash; must not include query.
        raw_query: Raw query string **without** the leading ``?``.
            Pass ``""`` when there is no query component.
        body: Raw request body bytes as they will be sent on the wire.
            Pass ``b""`` for GET/HEAD/OPTIONS or empty bodies.
        content_type: Content-Type header value.  Will be normalized
            (parameters stripped, lower-cased).  Pass ``None`` for
            GET/HEAD/OPTIONS/DELETE.

    Returns:
        A frozen :class:`~common.proof.models.ReqBinding` instance.
    """
    normalized_method = method.upper()
    query_hash = hash_query(raw_query)
    body_hash = hash_body(body) if body else EMPTY_HASH
    normalized_ct = normalize_content_type(content_type) if content_type else None

    return ReqBinding(
        method=normalized_method,  # type: ignore[arg-type]
        path=path,
        query_hash=query_hash,
        body_hash=body_hash,
        content_type=normalized_ct,
    )


def build_proof(
    private_key: Ed25519PrivateKey,
    *,
    consumer_did: str,
    kid: str,
    producer_did: str,
    env: str,
    req: ReqBinding,
    ttl: int = DEFAULT_PROOF_TTL,
    nonce: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> str:
    """Create and sign a ProofClaims JWT for the given request.

    The proof is signed with the Consumer Sentinel's Ed25519 private key
    and returned as a compact JWS string.  Attach it to the outgoing HTTP
    request as::

        Authorization: SentinelProof <compact_jws>

    Args:
        private_key: Consumer Sentinel's Ed25519 DID private key.
        consumer_did: ``did:key:z6Mk…`` — becomes ``iss``.
        kid: Verification method ID (``did:key:…#…``).
        producer_did: ``did:key:z6Mk…`` — becomes ``aud``.
        env: Deployment environment (``"dev"``, ``"test"``, or ``"prod"``).
        req: Pre-built :class:`~common.proof.models.ReqBinding`.
        ttl: Proof lifetime in seconds.  Must be 1–:data:`MAX_PROOF_TTL`.
        nonce: Optional session nonce returned by the Producer in a prior
            ``Sentinel-Nonce`` response header.
        trace_id: Optional OpenTelemetry trace-ID for observability.

    Returns:
        Compact JWS string.

    Raises:
        ValueError: If *ttl* is outside the allowed range.
    """
    if ttl <= 0 or ttl > MAX_PROOF_TTL:
        raise ValueError(
            f"ttl must be between 1 and {MAX_PROOF_TTL} seconds, got {ttl}."
        )

    now = int(time.time())
    jti = str(uuid.uuid4())

    claims_dict: dict = {
        "iss": consumer_did,
        "aud": producer_did,
        "env": env,
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
        "req": {
            "method": req.method,
            "path": req.path,
            "query_hash": req.query_hash,
            "body_hash": req.body_hash,
            "content_type": req.content_type,
        },
    }
    if nonce is not None:
        claims_dict["nonce"] = nonce
    if trace_id is not None:
        claims_dict["trace_id"] = trace_id

    return sign_jws(
        claims_dict,
        private_key,
        kid=kid,
        extra_headers={"typ": PROOF_TYP},
    )
