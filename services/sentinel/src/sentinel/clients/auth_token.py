"""Auth token management for the DiscoveryClient (TASK-040)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_RENEWAL_BUFFER_SECONDS = 300  # renew when less than 5 min left


@dataclass
class AuthToken:
    """In-memory bearer token with expiry tracking."""

    token: str
    exp: float  # Unix timestamp
    issued_at: float = field(default_factory=time.time)

    @classmethod
    def from_jwt(cls, jwt_string: str) -> "AuthToken":
        """Parse expiry directly from a JWT payload (no signature check)."""
        import base64, json

        parts = jwt_string.split(".")
        if len(parts) != 3:
            raise ValueError("Not a compact JWT")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        exp = float(payload.get("exp", time.time() + 3600))
        return cls(token=jwt_string, exp=exp)

    def is_expiring_soon(self, buffer: float = _RENEWAL_BUFFER_SECONDS) -> bool:
        return time.time() >= self.exp - buffer

    def is_expired(self) -> bool:
        return time.time() >= self.exp


class TokenManager:
    """Manages discovery auth-bearer token lifecycle."""

    def __init__(self) -> None:
        self._token: Optional[AuthToken] = None

    def set(self, jwt_string: str) -> None:
        self._token = AuthToken.from_jwt(jwt_string)
        logger.debug("Auth token updated, exp=%s", time.ctime(self._token.exp))

    def get(self) -> Optional[str]:
        if self._token and not self._token.is_expired():
            return self._token.token
        return None

    def needs_renewal(self) -> bool:
        if self._token is None:
            return False
        return self._token.is_expiring_soon()
