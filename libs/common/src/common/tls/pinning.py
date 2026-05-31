"""Certificate fingerprint pinning for Discovery server authentication.

When ``SENTINEL_CERT_PINNING=true`` and ``env=prod``, the TLS handshake is
followed by a fingerprint check.  A mismatch raises
:class:`CertificatePinViolation` and the connection is refused.

Usage::

    import ssl, socket
    ctx = create_strict_ssl_context(ca_cert_path="ca.crt")
    with socket.create_connection(("discovery", 443)) as raw:
        with ctx.wrap_socket(raw, server_hostname="discovery") as tls_sock:
            check_cert_fingerprint(tls_sock, expected_sha256="aabbccdd…")
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import ssl

logger = logging.getLogger(__name__)


class CertificatePinViolation(RuntimeError):
    """Raised when the server certificate SHA-256 fingerprint does not match."""


def check_cert_fingerprint(
    ssl_socket: ssl.SSLSocket,
    expected_sha256: str,
) -> None:
    """Verify the peer certificate fingerprint using constant-time comparison.

    Args:
        ssl_socket:       An *already-connected* TLS socket whose handshake has
                          completed.
        expected_sha256:  Hex-encoded SHA-256 fingerprint of the expected server
                          certificate (64 lower-case hex characters).

    Raises:
        CertificatePinViolation: if the actual fingerprint does not match.
        ValueError: if the socket has no peer certificate.
    """
    # Retrieve the DER-encoded peer certificate
    cert_der: bytes | None = ssl_socket.getpeercert(binary_form=True)  # type: ignore[assignment]
    if cert_der is None:
        raise ValueError("No peer certificate available on SSL socket.")

    actual = hashlib.sha256(cert_der).hexdigest()

    # Constant-time comparison to prevent timing side-channels
    if not hmac.compare_digest(actual.lower(), expected_sha256.lower()):
        logger.critical(
            "Certificate pin violation: expected=%s actual=%s host=%s",
            expected_sha256[:16] + "…",
            actual[:16] + "…",
            ssl_socket.server_hostname or "unknown",
        )
        raise CertificatePinViolation(
            f"Certificate fingerprint mismatch for host "
            f"'{ssl_socket.server_hostname}'. "
            "Connection refused."
        )

    logger.debug("Certificate pin OK for host=%s", ssl_socket.server_hostname)


def is_pinning_enabled(env: str) -> bool:
    """Return *True* when cert-pinning is active.

    Active only when ``SENTINEL_CERT_PINNING=true`` **and** ``env=="prod"``.
    """
    return (
        os.getenv("SENTINEL_CERT_PINNING", "false").lower() in ("true", "1", "yes")
        and env == "prod"
    )
