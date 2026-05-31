"""Redaction utilities applied at the logger boundary before any serialisation.

Rules:
1. JWT strings (three base64url segments) → ``<jwt_redacted>``
2. DID strings (did:<method>:<id>) → ``did:*:<SHA-256[:8]>``
3. bytes values → ``<bytes_redacted>``
4. Sensitive header keys (Authorization, SentinelVP, X-Api-Key) → ``<redacted>``
All rules applied recursively through nested dicts and lists.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

# Matches a 3-segment base64url JWT
_JWT_RE = re.compile(
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)

# Matches DID strings
_DID_RE = re.compile(r"did:[a-z]+:[A-Za-z0-9._%-]+")

# Headers whose values must be fully suppressed
_SENSITIVE_KEYS = frozenset(
    {"authorization", "sentinelvp", "x-api-key", "x-sentinel-vp"}
)


def _redact_string(value: str) -> str:
    """Apply JWT and DID redaction to a single string value."""
    # Replace JWTs first (they may contain dots that look like DIDs)
    value = _JWT_RE.sub("<jwt_redacted>", value)
    # Replace DID strings
    def _mask_did(m: re.Match[str]) -> str:  # type: ignore[type-arg]
        digest = hashlib.sha256(m.group(0).encode()).hexdigest()[:8]
        return f"did:*:{digest}"

    value = _DID_RE.sub(_mask_did, value)
    return value


def redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively apply all redaction rules to *d* and return a new dict."""
    result: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
            result[k] = "<redacted>"
        else:
            result[k] = _redact_value(v)
    return result


def _redact_value(v: Any) -> Any:  # noqa: ANN401
    if isinstance(v, bytes):
        return "<bytes_redacted>"
    if isinstance(v, str):
        return _redact_string(v)
    if isinstance(v, dict):
        return redact_dict(v)
    if isinstance(v, list):
        return [_redact_value(item) for item in v]
    return v


# ---------------------------------------------------------------------------
# Hash helpers (used by SentinelLogger)
# ---------------------------------------------------------------------------

def hash_field(value: str, length: int = 16) -> str:
    """Return the first *length* hex chars of the SHA-256 of *value*."""
    return hashlib.sha256(value.encode()).hexdigest()[:length]
