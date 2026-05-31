"""CurrentUser — the authenticated principal injected into admin endpoints."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CurrentUser:
    """Represents a validated, authenticated caller.

    Security notes:
    - ``raw_token`` must NEVER appear in logs or error responses.
    - ``sub`` (not ``email``) is recorded in every audit event.
    - ``actor_type="BREAK_GLASS"`` is used for emergency accounts.
    """

    sub: str
    roles: list[str] = field(default_factory=list)
    email: str = ""
    # Raw JWT used for downstream delegation — NEVER logged.
    raw_token: str = field(default="", repr=False)
    actor_type: str = "ADMIN"  # "BREAK_GLASS" for emergency access
