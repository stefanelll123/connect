"""Clock skew validation for proof JWT temporal claims (TASK-050).

``max_clock_skew_seconds`` MUST be fetched from TrustPolicyRegistry at call time
— never hardcoded — so the governance layer controls the allowed skew window.
"""
from __future__ import annotations

import logging
import time

from common.anti_replay.metrics import CLOCK_SKEW_VIOLATIONS

logger = logging.getLogger(__name__)


class ClockSkewError(Exception):
    """Raised when a JWT's temporal claims fall outside the allowed skew window.

    Attributes:
        code:          ``"CLOCK_SKEW_EXCEEDED"`` (iat too far in future) or
                       ``"PROOF_EXPIRED"`` (exp too far in the past).
        skew_seconds:  Absolute skew magnitude in seconds.
    """

    def __init__(self, code: str, skew_seconds: float) -> None:
        super().__init__(f"{code}: skew={skew_seconds:.2f}s")
        self.code = code
        self.skew_seconds = skew_seconds


def validate_temporal_claims(
    iat: float,
    exp: float,
    max_clock_skew_seconds: int,
    now: float | None = None,
) -> None:
    """Validate ``iat`` and ``exp`` against the configured clock skew window.

    The skew is bi-directional:
    - ``iat`` is allowed to be up to ``max_clock_skew_seconds`` in the future
      (to tolerate NTP drift on the producer side).
    - ``exp`` is allowed to be up to ``max_clock_skew_seconds`` in the past
      (to tolerate NTP drift on the consumer side).

    Args:
        iat:                    JWT ``iat`` claim (seconds since epoch).
        exp:                    JWT ``exp`` claim (seconds since epoch).
        max_clock_skew_seconds: Policy-controlled tolerance window.
        now:                    Override current time (for testing).

    Raises:
        ClockSkewError: with code ``CLOCK_SKEW_EXCEEDED`` if ``iat`` is too far
                        in the future, or ``PROOF_EXPIRED`` if ``exp`` is too far
                        in the past.
    """
    if now is None:
        now = time.time()

    # iat too far in the future — producer clock is ahead or replay of future-dated token
    if iat > now + max_clock_skew_seconds:
        skew = iat - now
        CLOCK_SKEW_VIOLATIONS.labels(direction="future").inc()
        logger.warning(
            "event=clock_skew_violation direction=future skew_seconds=%.2f"
            " iat=%.0f now=%.0f max_skew=%d",
            skew, iat, now, max_clock_skew_seconds,
        )
        raise ClockSkewError(code="CLOCK_SKEW_EXCEEDED", skew_seconds=skew)

    # exp too far in the past — token genuinely expired, not within acceptable skew
    # Boundary (exp == now - max_clock_skew_seconds) is still within the tolerated window.
    if exp < now - max_clock_skew_seconds:
        skew = now - exp
        CLOCK_SKEW_VIOLATIONS.labels(direction="past").inc()
        logger.warning(
            "event=clock_skew_violation direction=past skew_seconds=%.2f"
            " exp=%.0f now=%.0f max_skew=%d",
            skew, exp, now, max_clock_skew_seconds,
        )
        raise ClockSkewError(code="PROOF_EXPIRED", skew_seconds=skew)
