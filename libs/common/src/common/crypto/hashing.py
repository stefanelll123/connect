"""SHA-256 hashing utilities for ProofClaims request binding.

Provides helper functions that compute the ``req.body_hash`` and
``req.query_hash`` fields defined in the Sentinel ProofClaims spec
(see TASK-006).  Both values are base64url-encoded SHA-256 digests
transmitted without padding, matching the JWS/JWA convention for
base64url-encoded octet sequences.

References
----------
* RFC 4648 §5 — base64url encoding
* FIPS 180-4 — SHA-256
* Sentinel ProofClaims specification (TASK-006)
"""

from __future__ import annotations

import base64
import hashlib

__all__ = [
    "EMPTY_BODY_HASH",
    "sha256_b64url",
    "body_hash",
    "query_hash",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Pre-computed SHA-256 hash of the empty byte string, base64url-encoded
#: without padding.  Used when an HTTP request carries no body.
EMPTY_BODY_HASH: str = base64.urlsafe_b64encode(
    hashlib.sha256(b"").digest()
).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Core helper
# ---------------------------------------------------------------------------


def sha256_b64url(data: bytes) -> str:
    """Return the SHA-256 digest of *data* as a base64url string (no padding).

    Parameters
    ----------
    data:
        Raw bytes to hash.

    Returns
    -------
    str
        43-character base64url-encoded digest (256 bits / 6 bits-per-char,
        rounded up → 43 chars with trailing ``=`` stripped).
    """
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Semantic wrappers
# ---------------------------------------------------------------------------


def body_hash(raw_body: bytes | None) -> str:
    """Compute the ``req.body_hash`` value for a ProofClaims JWT.

    Parameters
    ----------
    raw_body:
        The raw request body bytes, or ``None`` / empty bytes for requests
        that carry no body (GET, HEAD, DELETE without body).

    Returns
    -------
    str
        Base64url-encoded SHA-256 hash suitable for use as
        ``ProofClaims.req.body_hash``.
    """
    if not raw_body:
        return EMPTY_BODY_HASH
    return sha256_b64url(raw_body)


def query_hash(raw_query: str | bytes | None) -> str:
    """Compute the ``req.query_hash`` value for a ProofClaims JWT.

    The query string is hashed as-is (percent-encoded, without the leading
    ``?``).  An absent or empty query string produces :data:`EMPTY_BODY_HASH`
    (the SHA-256 of the empty string).

    Parameters
    ----------
    raw_query:
        The raw query string (without the leading ``?``), or ``None`` / empty
        string for requests with no query parameters.  If given as ``str``,
        it is encoded to UTF-8 before hashing.

    Returns
    -------
    str
        Base64url-encoded SHA-256 hash suitable for use as
        ``ProofClaims.req.query_hash``.
    """
    if not raw_query:
        return EMPTY_BODY_HASH
    raw_bytes = raw_query.encode() if isinstance(raw_query, str) else raw_query
    return sha256_b64url(raw_bytes)
