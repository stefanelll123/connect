"""SentinelLogEvent dataclass — the canonical structured log event schema.

All sentinel log entries are serialised from an instance of this class.
No raw secrets, JWTs, or DIDs are stored here — only pre-redacted fields.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SentinelLogEvent:
    """Structured log event schema for all sentinel request/activity logging."""

    # Mandatory fields
    ts: str                          # ISO-8601 UTC  e.g. "2026-03-15T10:00:00Z"
    level: str                       # INFO | WARNING | ERROR
    event: str                       # snake_case event type

    service_id: str
    env: str
    role: str                        # producer | consumer

    # Optional contextual fields
    direction: str | None = None     # inbound | outbound | internal
    request_id: str | None = None
    decision: str | None = None      # permit | deny
    error_code: str | None = None

    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    latency_ms: float | None = None

    # Security correlation (truncated hashes only — never raw values)
    jti_hash: str | None = None      # SHA-256[:16] of JTI
    consumer_did_hash: str | None = None  # SHA-256[:16] of consumer DID

    trace_id: str | None = None

    # Pre-redacted extra context (warning/error enrichment)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict, omitting None values for compactness."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None and v != {}}

    def to_json(self) -> str:
        """Serialise to a single-line UTF-8 JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))
