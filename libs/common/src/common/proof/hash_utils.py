"""Body and query hash utilities for the Request Security Envelope.

All hashes are base64url-encoded SHA-256 digests of **raw bytes** — not of
parsed or decoded representations.  This is intentional: the Producer
Sentinel must hash the exact bytes it receives over the wire, which must
match the hash the Consumer computed before signing the proof.

Key invariant:
  hash_bytes(b'') == EMPTY_HASH

  This value is used for GET/HEAD/OPTIONS requests with no body, and for
  requests with no query string.
"""

from __future__ import annotations

import base64
import hashlib

__all__ = [
    "EMPTY_HASH",
    "hash_bytes",
    "hash_query",
    "hash_body",
    "normalize_content_type",
]

# ---------------------------------------------------------------------------
# Constant: SHA-256 of the empty byte string, base64url-encoded
# ---------------------------------------------------------------------------

# Verified: hashlib.sha256(b'').digest() base64url-encoded (no padding)
EMPTY_HASH: str = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

# Methods that carry no body; always use EMPTY_HASH for body_hash.
_BODYLESS_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Hard cap on body size to hash (4 MiB).  Callers should enforce before
# passing bytes to hash_body().
MAX_BODY_BYTES = 4 * 1024 * 1024  # 4 MiB


def hash_bytes(data: bytes) -> str:
    """Return base64url(SHA-256(*data*)) with no padding characters.

    This is the canonical hash function used for both query strings and
    request bodies throughout the security envelope.

    .. important::
       Always pass **raw, undecoded** bytes — never a decoded string or a
       re-serialized representation.  The hash must match what the peer
       computes from the wire bytes.

    Args:
        data: Raw bytes to hash.  May be empty (returns :data:`EMPTY_HASH`).

    Returns:
        Unpadded base64url string of the 32-byte SHA-256 digest.
    """
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def hash_query(raw_query: str) -> str:
    """Compute the query hash for a raw query string.

    Args:
        raw_query: The raw query string portion of the URL **without** the
            leading ``?``.  Pass an empty string (``""``) when there is no
            query component.

    Returns:
        ``base64url(SHA-256(raw_query.encode('utf-8')))`` — or
        :data:`EMPTY_HASH` when *raw_query* is empty.
    """
    return hash_bytes(raw_query.encode("utf-8"))


def hash_body(body: bytes) -> str:
    """Compute the body hash for a raw request body.

    Args:
        body: Raw request body bytes.  Pass ``b""`` for GET/HEAD/OPTIONS
            requests or when the body is empty.

    Returns:
        ``base64url(SHA-256(body))`` — or :data:`EMPTY_HASH` when *body*
        is empty.

    Raises:
        ValueError: If *body* exceeds :data:`MAX_BODY_BYTES`.
    """
    if len(body) > MAX_BODY_BYTES:
        raise ValueError(
            f"Request body ({len(body)} bytes) exceeds the maximum hashable "
            f"size ({MAX_BODY_BYTES} bytes).  Reject the request."
        )
    return hash_bytes(body)


def body_hash_for_method(method: str, body: bytes) -> str:
    """Return the canonical body hash for *method* + *body*.

    For bodyless HTTP methods (GET, HEAD, OPTIONS, TRACE), always returns
    :data:`EMPTY_HASH` regardless of the supplied *body* bytes.  For all
    other methods, delegates to :func:`hash_body`.

    Args:
        method: HTTP method string (case-insensitive).
        body: Raw body bytes as received from the wire.

    Returns:
        base64url SHA-256 hash.
    """
    if method.upper() in _BODYLESS_METHODS:
        return EMPTY_HASH
    return hash_body(body)


def normalize_content_type(content_type: str) -> str:
    """Strip parameters from *content_type* and lower-case it.

    Example::

        normalize_content_type("application/json; charset=utf-8")
        # → "application/json"

    Args:
        content_type: Raw value of the Content-Type HTTP header.

    Returns:
        Normalized media type string suitable for embedding in ReqBinding.
    """
    return content_type.split(";")[0].strip().lower()
