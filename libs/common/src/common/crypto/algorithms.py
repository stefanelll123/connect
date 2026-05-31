"""Algorithm constants and enforcement for the Sentinel crypto suite.

This module is the authoritative source for which signing algorithms are allowed,
optional, or prohibited in the system. All higher-level JWT/JWS utilities MUST
import from here and MUST NOT hard-code algorithm names.

Security design: The prohibited set is checked at parse time, before any signature
verification, so a ``alg: none`` attack is rejected before the key is ever consulted.
"""

from __future__ import annotations

__all__ = [
    "REQUIRED_ALGS",
    "OPTIONAL_ALGS",
    "ALLOWED_ALGS",
    "PROHIBITED_ALGS",
    "ProhibitedAlgorithmError",
    "assert_algorithm_allowed",
]


# ---------------------------------------------------------------------------
# Algorithm sets
# ---------------------------------------------------------------------------

#: Algorithms that MUST be supported by all implementations.
REQUIRED_ALGS: frozenset[str] = frozenset({"EdDSA"})

#: Algorithms that MAY be supported (e.g. HSMs that do not expose Ed25519).
OPTIONAL_ALGS: frozenset[str] = frozenset({"ES256"})

#: Union of required and optional — the only values accepted in a JOSE header.
ALLOWED_ALGS: frozenset[str] = REQUIRED_ALGS | OPTIONAL_ALGS

#: Algorithms that are explicitly rejected even if the underlying library
#: would otherwise accept them.  Checked before any cryptographic operation.
PROHIBITED_ALGS: frozenset[str] = frozenset(
    {
        # Symmetric / secret-sharing — unsuitable for multi-party trust
        "HS256",
        "HS384",
        "HS512",
        # Weak RSA modes prone to key confusion and downgrade attacks
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        # Algorithm confusion — must be rejected by name in all its casing variants
        "none",
        "None",
        "NONE",
        "",
    }
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProhibitedAlgorithmError(ValueError):
    """Raised when a JOSE header contains a prohibited algorithm.

    This is a :class:`ValueError` so callers can catch it without importing
    this module — but they *should* prefer catching this specific type for
    clarity in error handling.
    """

    def __init__(self, alg: str) -> None:
        super().__init__(
            f"Algorithm '{alg}' is prohibited by the Sentinel crypto policy. "
            f"Allowed: {sorted(ALLOWED_ALGS)}"
        )
        self.alg = alg


# ---------------------------------------------------------------------------
# Enforcement helper
# ---------------------------------------------------------------------------


def assert_algorithm_allowed(alg: str | None) -> str:
    """Validate *alg* against the algorithm policy.

    Parameters
    ----------
    alg:
        The value of the ``alg`` JOSE header parameter.  ``None`` or the
        empty string are treated identically to ``alg: none`` and rejected.

    Returns
    -------
    str
        The validated algorithm name (unchanged).

    Raises
    ------
    ProhibitedAlgorithmError
        If *alg* is in :data:`PROHIBITED_ALGS` or not in :data:`ALLOWED_ALGS`.
    """
    # Normalise: treat None / empty string as the "none" algorithm attack
    normalised = alg or "none"

    if normalised in PROHIBITED_ALGS:
        raise ProhibitedAlgorithmError(normalised)

    if normalised not in ALLOWED_ALGS:
        raise ProhibitedAlgorithmError(normalised)

    return normalised
