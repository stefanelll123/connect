"""TLS SSLContext factory with TLS 1.2+ enforcement and strong cipher suites.

Usage::

    from common.tls.context import create_strict_ssl_context
    ctx = create_strict_ssl_context(
        ca_cert_path="/path/to/ca.crt",
        client_cert_path="/path/to/client.crt",
        client_key_path="/path/to/client.key",
    )
    import httpx
    async with httpx.AsyncClient(verify=ctx) as client:
        ...
"""
from __future__ import annotations

import ssl


# Strong cipher suite string — explicit allow-list, explicit deny-list
_STRONG_CIPHERS = ":".join([
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "DHE+AESGCM",
    "!aNULL",
    "!eNULL",
    "!EXPORT",
    "!DES",
    "!RC4",
    "!3DES",
])


class ConfigurationError(RuntimeError):
    """Raised when mandatory TLS/mTLS configuration is absent or invalid."""


def create_strict_ssl_context(
    ca_cert_path: str | None = None,
    client_cert_path: str | None = None,
    client_key_path: str | None = None,
) -> ssl.SSLContext:
    """Create an :class:`ssl.SSLContext` enforcing TLS 1.2+ with strong ciphers.

    Args:
        ca_cert_path:      Path to a custom CA bundle for server certificate
                            verification.  If *None*, the system default CA store
                            is used.
        client_cert_path:  Path to the client certificate (PEM) for mTLS.
        client_key_path:   Path to the client private key (PEM) for mTLS.
                            Must be supplied together with *client_cert_path*.

    Returns:
        A configured :class:`ssl.SSLContext`.

    Raises:
        ConfigurationError: if *client_cert_path* is supplied without
            *client_key_path* (or vice-versa), or if a certificate file cannot
            be loaded.
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    # Enforce TLS 1.2 as the minimum acceptable version
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Restrict to strong cipher suites
    ctx.set_ciphers(_STRONG_CIPHERS)

    # Disable TLS compression (CRIME attack vector)
    ctx.options |= ssl.OP_NO_COMPRESSION

    # Custom CA store for private PKI / pinning environments
    if ca_cert_path is not None:
        try:
            ctx.load_verify_locations(ca_cert_path)
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(
                f"Cannot load CA certificate from '{ca_cert_path}': {exc}"
            ) from exc

    # mTLS client certificate
    if client_cert_path is not None or client_key_path is not None:
        if not client_cert_path or not client_key_path:
            raise ConfigurationError(
                "Both client_cert_path and client_key_path must be supplied "
                "for mTLS, or neither."
            )
        try:
            ctx.load_cert_chain(client_cert_path, client_key_path)
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(
                f"Cannot load mTLS client certificate from "
                f"'{client_cert_path}'/'{client_key_path}': {exc}"
            ) from exc

    return ctx
