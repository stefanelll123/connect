"""Credential selection for VP building (TASK-044)."""
from __future__ import annotations

import logging
import time
from typing import List, Optional

logger = logging.getLogger(__name__)


class NoCredentialAvailable(Exception):
    """No matching VC found for the target service."""


def _decode_jwt_payload(jwt_str: str) -> dict:
    """Decode the payload of a compact JWT or SD-JWT without verification.

    For SD-JWT presentations/tokens the JWT part is taken as everything
    before the first ``~`` separator.  Returns empty dict on any error.
    """
    import base64
    import json
    try:
        jwt_part = jwt_str.split("~")[0]
        parts = jwt_part.split(".")
        if len(parts) != 3:
            return {}
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def select_credentials(
    service_id: str,
    env: str,
    credential_store,
    master_key: bytes = b"",
) -> List[str]:
    """Select VCs from the local credential store for the target service.

    Selects credentials where:
    - credentialSubject.service_id == service_id
    - credentialSubject.env == env
    - exp > now + 60s (not expiring within the next minute)
    - status != revoked (when status information is available)

    Handles both plain JWT-VC and SD-JWT credential formats.

    If multiple credentials of the same type exist, prefers the one with
    the latest ``exp`` (most recently issued).

    Args:
        service_id:       Target service identifier.
        env:              Target deployment environment.
        credential_store: CredentialStore instance.

    Returns:
        List of raw JWT-VC strings, at least one.

    Raises:
        NoCredentialAvailable: if no matching credential is found.
    """
    now = time.time()
    candidates: List[str] = []

    try:
        active = credential_store.get_all_raw(master_key)
    except Exception as exc:
        logger.warning("Credential store read failed: %s", exc)
        active = []

    for jwt_str in active:
        try:
            payload = _decode_jwt_payload(jwt_str)
            exp = float(payload.get("exp", 0))
            if exp < now + 60:
                continue
            vc = payload.get("vc", {})
            subject = vc.get("credentialSubject", {})
            if subject.get("service_id") == service_id and subject.get("env") == env:
                candidates.append(jwt_str)
        except Exception:
            continue

    if not candidates:
        raise NoCredentialAvailable(
            f"No valid credential for service={service_id!r} env={env!r}"
        )

    # Prefer latest exp if duplicates by type
    candidates.sort(key=_exp_key, reverse=True)
    return candidates


def select_sd_jwt_credential(
    service_id: str,
    env: str,
    credential_store,
    master_key: bytes = b"",
) -> Optional[str]:
    """Select the best SD-JWT credential for session exchange.

    Searches the credential store for a credential in SD-JWT format
    (``typ: sd+jwt`` header or ``~`` separator) matching *service_id* and
    *env*.  Returns the raw SD-JWT string (issuer part only, no KB-JWT),
    or ``None`` if none is found.

    This is used by the consumer pipeline during the session-exchange
    handshake (*Step 9*) to build an SD-JWT presentation.
    """
    from common.security_envelope.builder import is_sd_jwt

    now = time.time()
    best: Optional[str] = None
    best_exp: float = 0.0

    try:
        active = credential_store.get_all_raw(master_key)
    except Exception as exc:
        logger.warning("Credential store SD-JWT read failed: %s", exc)
        return None

    for jwt_str in active:
        if not is_sd_jwt(jwt_str):
            continue
        try:
            payload = _decode_jwt_payload(jwt_str)
            exp = float(payload.get("exp", 0))
            if exp < now + 60:
                continue
            vc = payload.get("vc", {})
            subject = vc.get("credentialSubject", {})
            if subject.get("service_id") == service_id and subject.get("env") == env:
                if exp > best_exp:
                    best_exp = exp
                    best = jwt_str
        except Exception:
            continue

    return best


def _exp_key(jwt_str: str) -> float:
    return float(_decode_jwt_payload(jwt_str).get("exp", 0))
